//! Shared ECDH-ES JWE plumbing for the OpenID4VCI and OpenID4VP protocols.
//!
//! The cryptography itself lives in [`one_crypto::jwe`]; this module only binds it to the
//! one-core key algorithm and key storage providers.

use one_crypto::jwe::{Header, decrypt_jwe_payload};
use standardized_types::iana::EncryptionAlgorithm;
use standardized_types::jwk::{JwkUse, PublicJwk};

use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt, NestedError};
use crate::model::key::Key;
use crate::provider::key_algorithm::provider::{KeyAlgorithmProvider, ParsedKey};
use crate::provider::key_storage::provider::KeyProvider;

/// Builds an ECDH-ES JWE addressed to `recipient_key`.
///
/// The ephemeral key is generated for the recipient's own key algorithm, so the curve always
/// matches. The caller fills `header` with the protocol specific parts (`kid`, `zip`, `apu`,
/// `apv`).
pub(crate) async fn build_jwe(
    payload: &[u8],
    recipient_key: &PublicJwk,
    header: Header,
    encryption_algorithm: EncryptionAlgorithm,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<String, NestedError> {
    let ParsedKey { algorithm_type, .. } = key_algorithm_provider
        .parse_jwk(recipient_key)
        .error_while("parsing JWK")?;
    let algorithm = key_algorithm_provider.key_algorithm_from_type(algorithm_type)?;

    let private_key = algorithm
        .generate_key()
        .error_while("generating encryption key")?;
    let key_agreement = private_key
        .key
        .key_agreement()
        .ok_or_else(|| JweError::NoKeyAgreement.error_while("preparing encryption key"))?;
    let shared_secret = key_agreement
        .private()
        .ok_or_else(|| JweError::NoPrivateKey.error_while("preparing encryption key"))?
        .shared_secret(recipient_key)
        .await
        .error_while("deriving shared secret")?;
    let local_jwk = key_agreement
        .public()
        .as_jwk()
        .error_while("generating local JWK")?;

    one_crypto::jwe::build_jwe(
        payload,
        header,
        shared_secret,
        local_jwk,
        encryption_algorithm,
    )
    .error_while("building JWE")
}

/// Decrypts an ECDH-ES JWE addressed to `key`.
pub(crate) async fn decrypt_jwe(
    jwe: &str,
    key: &Key,
    key_provider: &dyn KeyProvider,
) -> Result<Vec<u8>, NestedError> {
    let key_handle = key_provider
        .get_key_storage(&key.storage_type)?
        .key_handle(key)
        .error_while("getting key handle")?;

    let private_key = key_handle
        .key_agreement()
        .and_then(|key_agreement| key_agreement.private())
        .ok_or_else(|| JweError::NoKeyAgreement.error_while("selecting decryption key"))?;

    decrypt_jwe_payload(jwe, private_key.as_ref())
        .await
        .error_while("decrypting JWE")
}

/// Picks the first key of a peer's JWKS usable as an ECDH-ES recipient.
///
/// Per RFC 7517 §4.2, `use` is OPTIONAL. When absent, the key's algorithm or capabilities
/// determine its purpose, so only keys explicitly marked for a non-encryption use (e.g. `sig`)
/// are rejected. The key also has to be one we can actually perform a key agreement with.
pub(crate) fn select_recipient_jwk(
    keys: impl IntoIterator<Item = PublicJwk>,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Option<PublicJwk> {
    let is_usable_for_encryption = |key: &PublicJwk| -> bool {
        match key.r#use() {
            Some(r#use) => *r#use == JwkUse::Encryption,
            None => true,
        }
    };

    let supports_key_agreement = |key: &PublicJwk| -> bool {
        key_algorithm_provider
            .parse_jwk(key)
            .is_ok_and(|parsed_key| parsed_key.key.key_agreement().is_some())
    };

    keys.into_iter()
        .find(|key| is_usable_for_encryption(key) && supports_key_agreement(key))
}

#[derive(Debug, thiserror::Error)]
enum JweError {
    #[error("key does not support key agreement")]
    NoKeyAgreement,
    #[error("key agreement handle has no private key")]
    NoPrivateKey,
}

impl crate::error::ErrorCodeMixin for JweError {
    fn error_code(&self) -> crate::error::ErrorCode {
        crate::error::ErrorCode::BR_0062
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use one_crypto::jwe::decrypt_jwe_payload;
    use similar_asserts::assert_eq;
    use standardized_types::jwk::PublicJwkEc;

    use super::*;
    use crate::config::core_config::KeyAlgorithmType;
    use crate::provider::key_algorithm::KeyAlgorithm;
    use crate::provider::key_algorithm::ecdsa::Ecdsa;
    use crate::provider::key_algorithm::eddsa::Eddsa;
    use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;

    /// A provider delegating to a single real key algorithm, so the round trips exercise the
    /// actual ECDH implementations rather than mocks.
    fn provider_for(
        algorithm: Arc<dyn KeyAlgorithm>,
        algorithm_type: KeyAlgorithmType,
    ) -> MockKeyAlgorithmProvider {
        let mut provider = MockKeyAlgorithmProvider::new();
        let parse = algorithm.clone();
        provider.expect_parse_jwk().returning(move |jwk| {
            Ok(ParsedKey {
                key: parse
                    .parse_jwk(jwk)
                    .error_while("parsing JWK in test provider")?,
                algorithm_type,
            })
        });
        provider
            .expect_key_algorithm_from_type()
            .returning(move |_| Ok(algorithm.clone()));
        provider
    }

    async fn assert_round_trip(algorithm: Arc<dyn KeyAlgorithm>, algorithm_type: KeyAlgorithmType) {
        let provider = provider_for(algorithm.clone(), algorithm_type);

        // the recipient's static key; the JWK has to come from the key agreement handle, which
        // for EdDSA is the X25519 conversion rather than the Ed25519 point
        let recipient = algorithm.generate_key().unwrap();
        let recipient_agreement = recipient.key.key_agreement().unwrap();
        let recipient_jwk = recipient_agreement.public().as_jwk().unwrap();

        let payload = b"the credential response";
        let jwe = build_jwe(
            payload,
            &recipient_jwk,
            Header {
                key_id: Some("key-1".to_string()),
                zip: None,
                partyuinfo_data: Some(b"apu".to_vec()),
                partyvinfo_data: Some(b"apv".to_vec()),
            },
            EncryptionAlgorithm::A256GCM,
            &provider,
        )
        .await
        .unwrap();

        let header = one_crypto::jwe::extract_jwe_header(&jwe).unwrap();
        assert_eq!(Some("key-1".to_string()), header.key_id);
        assert_eq!(Some(b"apu".to_vec()), header.partyuinfo_data);
        assert_eq!(Some(b"apv".to_vec()), header.partyvinfo_data);

        let decrypted = decrypt_jwe_payload(&jwe, recipient_agreement.private().unwrap().as_ref())
            .await
            .unwrap();
        assert_eq!(payload.to_vec(), decrypted);
    }

    #[tokio::test]
    async fn test_build_jwe_round_trip_ecdsa() {
        assert_round_trip(Arc::new(Ecdsa), KeyAlgorithmType::Ecdsa).await;
    }

    #[tokio::test]
    async fn test_build_jwe_round_trip_eddsa() {
        assert_round_trip(Arc::new(Eddsa), KeyAlgorithmType::Eddsa).await;
    }

    fn ecdsa_encryption_jwk() -> PublicJwk {
        Ecdsa
            .generate_key()
            .unwrap()
            .key
            .key_agreement()
            .unwrap()
            .public()
            .as_jwk()
            .unwrap()
    }

    /// The same key, but explicitly marked as a signature key.
    fn ecdsa_signature_jwk() -> PublicJwk {
        match ecdsa_encryption_jwk() {
            PublicJwk::Ec(mut key) => {
                key.r#use = Some(JwkUse::Signature);
                PublicJwk::Ec(key)
            }
            other => panic!("expected an EC key, got {other:?}"),
        }
    }

    #[test]
    fn test_select_recipient_jwk_skips_signature_keys() {
        let signing_key = ecdsa_signature_jwk();
        let encryption_key = ecdsa_encryption_jwk();

        let provider = provider_for(Arc::new(Ecdsa), KeyAlgorithmType::Ecdsa);

        let selected =
            select_recipient_jwk([signing_key, encryption_key.clone()], &provider).unwrap();
        assert_eq!(encryption_key, selected);
    }

    #[test]
    fn test_select_recipient_jwk_skips_keys_that_cannot_do_key_agreement() {
        let provider = provider_for(Arc::new(Ecdsa), KeyAlgorithmType::Ecdsa);

        // a key the provider cannot parse can never be a key agreement recipient
        let unparseable = PublicJwk::Ec(PublicJwkEc {
            alg: None,
            r#use: None,
            kid: None,
            crv: "P-256".to_string(),
            x: "not-a-key".to_string(),
            y: Some("not-a-key".to_string()),
        });
        let encryption_key = ecdsa_encryption_jwk();

        let selected =
            select_recipient_jwk([unparseable, encryption_key.clone()], &provider).unwrap();
        assert_eq!(encryption_key, selected);
    }

    #[test]
    fn test_select_recipient_jwk_returns_none_when_nothing_usable() {
        let provider = provider_for(Arc::new(Ecdsa), KeyAlgorithmType::Ecdsa);

        assert!(select_recipient_jwk([ecdsa_signature_jwk()], &provider).is_none());
    }
}
