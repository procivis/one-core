use one_crypto::jwe::{Header, decrypt_jwe_payload};
use standardized_types::iana::EncryptionAlgorithm;
use standardized_types::jwe::CompressionAlgorithm;
use standardized_types::jwk::PublicJwk;

use crate::error::ContextWithErrorCode;
use crate::model::key::Key;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::key_algorithm::provider::{KeyAlgorithmProvider, ParsedKey};
use crate::provider::key_storage::provider::KeyProvider;

pub(crate) async fn build_jwe(
    payload: &[u8],
    recipient_key: PublicJwk,
    encryption_algorithm: EncryptionAlgorithm,
    compression: Option<CompressionAlgorithm>,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<String, IssuanceProtocolError> {
    let ParsedKey { algorithm_type, .. } = key_algorithm_provider
        .parse_jwk(&recipient_key)
        .error_while("Parsing JWK")?;
    let algorithm = key_algorithm_provider.key_algorithm_from_type(algorithm_type)?;

    let private_key = algorithm
        .generate_key()
        .error_while("Generating encryption key")?;
    let key_agreement = private_key
        .key
        .key_agreement()
        .ok_or(IssuanceProtocolError::Failed(
            "Key agreement not set".to_string(),
        ))?;
    let shared_secret = key_agreement
        .private()
        .ok_or(IssuanceProtocolError::Failed(
            "Private key not set".to_string(),
        ))?
        .shared_secret(&recipient_key)
        .await?;
    let local_jwk = key_agreement
        .public()
        .as_jwk()
        .error_while("Generating local JWK")?;

    Ok(one_crypto::jwe::build_jwe(
        payload,
        Header {
            key_id: recipient_key.kid().map(String::from),
            zip: compression,
            partyuinfo_data: None,
            partyvinfo_data: None,
        },
        shared_secret,
        local_jwk,
        encryption_algorithm,
    )?)
}

/// Decrypts an ECDH-ES JWE addressed to `key`.
pub(crate) async fn decrypt_jwe(
    jwe: &str,
    key: &Key,
    key_provider: &dyn KeyProvider,
) -> Result<Vec<u8>, IssuanceProtocolError> {
    let key_handle = key_provider
        .get_key_storage(&key.storage_type)?
        .key_handle(key)
        .error_while("getting key handle")?;

    let private_key = key_handle
        .key_agreement()
        .and_then(|key_agreement| key_agreement.private())
        .ok_or(IssuanceProtocolError::Failed(
            "Key does not support key agreement".to_string(),
        ))?;

    Ok(decrypt_jwe_payload(jwe, private_key.as_ref()).await?)
}
