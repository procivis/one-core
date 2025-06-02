use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use time::OffsetDateTime;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::model::{DecomposedToken, JWTPayload};
use crate::provider::credential_formatter::jwt::{Jwt, JwtPublicKeyInfo};
use crate::provider::credential_formatter::model::{
    AuthenticationFn, PublicKeySource, TokenVerifier,
};
use crate::service::key::dto::PublicKeyJwkDTO;

const JWT_PROOF_TYPE: &str = "openid4vci-proof+jwt";

pub struct OpenID4VCIProofJWTFormatter {}

#[derive(Debug, Default, Deserialize)]
pub struct ProofOfPossession {
    pub nonce: Option<String>,
}

impl OpenID4VCIProofJWTFormatter {
    pub async fn verify_proof(
        jwt: &str,
        verifier: Box<dyn TokenVerifier>,
        expected_nonce: Option<String>,
    ) -> Result<(DidValue, String), FormatterError> {
        let DecomposedToken::<ProofOfPossession> {
            header,
            payload,
            signature,
            unverified_jwt,
        } = Jwt::decompose_token(jwt)?;

        match header.r#type.as_deref() {
            Some(JWT_PROOF_TYPE) => {}
            Some(other) => {
                return Err(FormatterError::CouldNotVerify(format!(
                    "Invalid proof.jwt type: {other}"
                )));
            }
            None => {
                return Err(FormatterError::CouldNotVerify(
                    "Missing proof.jwt type".to_string(),
                ));
            }
        }
        if let Some(expected_nonce) = expected_nonce {
            if payload.custom.nonce.as_ref() != Some(&expected_nonce) {
                return Err(FormatterError::CouldNotVerify(format!(
                    "invalid or missing nonce: expected: {expected_nonce}"
                )));
            }
        }

        let result = match (header.key_id.as_ref(), header.jwk.clone()) {
            (Some(_), Some(_)) => {
                return Err(FormatterError::CouldNotVerify(
                    "Only kid or jwt allowed in proof.jwt but not both".to_string(),
                ));
            }
            (None, None) => {
                return Err(FormatterError::CouldNotVerify(
                    "Missing kid or jwk".to_string(),
                ));
            }
            (Some(key_id), None) => {
                let (did, fragment) = match key_id.find('#') {
                    // key_id is verificationMethod id
                    Some(idx) => (&key_id[..idx], Some(key_id.as_str())),
                    None => (key_id.as_str(), None),
                };

                let did: DidValue = did
                    .parse()
                    .map_err(|e| FormatterError::CouldNotVerify(format!("Invalid did: {e}")))?;

                let (_, key_algorithm) = verifier
                    .key_algorithm_provider()
                    .key_algorithm_from_jose_alg(&header.algorithm)
                    .ok_or(FormatterError::CouldNotVerify(
                        "Invalid key algorithm".to_string(),
                    ))?;

                let params = PublicKeySource::Did {
                    did: &did,
                    key_id: fragment,
                };
                verifier
                    .verify(
                        params,
                        key_algorithm.algorithm_type(),
                        unverified_jwt.as_bytes(),
                        &signature,
                    )
                    .await
                    .map_err(|e| {
                        FormatterError::CouldNotVerify(format!("Failed to verify proof.jwt: {e}"))
                    })?;
                (did, key_id.clone())
            }
            (None, Some(jwk)) => {
                let jwk = jwk.into();

                let key_handle =
                    verifier
                        .key_algorithm_provider()
                        .parse_jwk(&jwk)
                        .map_err(|e| {
                            FormatterError::CouldNotVerify(format!(
                                "Could not parse jwk from proof.jwt: {e}"
                            ))
                        })?;

                key_handle
                    .key
                    .verify(unverified_jwt.as_bytes(), &signature)
                    .map_err(|_| FormatterError::CouldNotVerify("Invalid signature".to_string()))?;
                let multibase = key_handle.key.public_key_as_multibase().map_err(|err| {
                    FormatterError::CouldNotVerify(format!(
                        "Failed to encode public key as multibase: {err}"
                    ))
                })?;
                let did_value = format!("did:key:{multibase}");
                let key_id = format!("{did_value}#{multibase}");
                let did_value = did_value
                    .parse()
                    .map_err(|e| FormatterError::CouldNotVerify(format!("Invalid did: {e}")))?;
                (did_value, key_id)
            }
        };
        Ok(result)
    }

    pub async fn format_proof(
        issuer_url: String,
        holder_key_id: Option<String>,
        jwk: Option<PublicKeyJwkDTO>,
        nonce: Option<String>,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        #[derive(Serialize)]
        struct NonceClaim {
            nonce: String,
        }

        let custom = nonce.map(|nonce| NonceClaim { nonce });
        let payload = JWTPayload {
            audience: Some(vec![issuer_url]),
            custom,
            issued_at: Some(OffsetDateTime::now_utc()),
            ..Default::default()
        };

        let key_id = match jwk {
            Some(_) => None,
            None => holder_key_id,
        };
        let jwk = jwk.map(JwtPublicKeyInfo::Jwk);

        let jwt = Jwt::new(
            JWT_PROOF_TYPE.to_string(),
            auth_fn.jose_alg().ok_or(FormatterError::CouldNotFormat(
                "Invalid key algorithm".to_string(),
            ))?,
            key_id,
            jwk,
            payload,
        );

        jwt.tokenize(Some(auth_fn)).await
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::sync::Arc;

    use uuid::Uuid;

    use super::*;
    use crate::config::core_config::KeyAlgorithmType;
    use crate::model::did::KeyRole;
    use crate::model::key::{Key, PublicKeyJwk};
    use crate::provider::credential_formatter::model::SignatureProvider;
    use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
    use crate::provider::did_method::provider::MockDidMethodProvider;
    use crate::provider::key_algorithm::KeyAlgorithm;
    use crate::provider::key_algorithm::eddsa::Eddsa;
    use crate::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
    use crate::provider::key_storage::provider::SignatureProviderImpl;
    use crate::service::certificate::validator::MockCertificateValidator;
    use crate::util::key_verification::KeyVerification;

    #[tokio::test]
    async fn test_format_then_verify_proof_with_holder_key_id() {
        let auth_fn = auth_fn();
        let holder_key_id = did_key();

        let proof = OpenID4VCIProofJWTFormatter::format_proof(
            "https://example.com".to_string(),
            Some(format!("{holder_key_id}#key-1")),
            None,
            None,
            auth_fn,
        )
        .await
        .unwrap();

        OpenID4VCIProofJWTFormatter::verify_proof(&proof, verifier(), None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_format_then_verify_proof_with_jwk() {
        let auth_fn = auth_fn();
        let jwk = pk_jwk();

        let proof = OpenID4VCIProofJWTFormatter::format_proof(
            "https://example.com".to_string(),
            None,
            Some(jwk.into()),
            Some("nonce".to_string()),
            auth_fn,
        )
        .await
        .unwrap();

        OpenID4VCIProofJWTFormatter::verify_proof(&proof, verifier(), Some("nonce".to_string()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_format_then_verify_proof_with_jwk_invalid_nonce() {
        let auth_fn = auth_fn();
        let jwk = pk_jwk();

        let proof = OpenID4VCIProofJWTFormatter::format_proof(
            "https://example.com".to_string(),
            None,
            Some(jwk.into()),
            Some("nonce".to_string()),
            auth_fn,
        )
        .await
        .unwrap();

        let result = OpenID4VCIProofJWTFormatter::verify_proof(
            &proof,
            verifier(),
            Some("invalid_nonce".to_string()),
        )
        .await;
        assert!(matches!(result, Err(FormatterError::CouldNotVerify(_))));
    }

    #[track_caller]
    fn verifier() -> Box<dyn TokenVerifier> {
        let mut did_method_provider = MockDidMethodProvider::new();
        let did = did_key();
        did_method_provider.expect_resolve().returning(move |_| {
            let selected_key = format!("{did}#key-1");

            Ok(DidDocument {
                id: did.clone(),
                verification_method: vec![DidVerificationMethod {
                    id: selected_key.clone(),
                    r#type: "Ed25519".to_string(),
                    controller: "did:example:123".to_string(),
                    public_key_jwk: pk_jwk(),
                }],
                authentication: Some(vec![selected_key]),
                context: serde_json::json!({}),
                assertion_method: None,
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                also_known_as: None,
                service: None,
            })
        });

        let key_algorithm_provider =
            Arc::new(KeyAlgorithmProviderImpl::new(HashMap::from_iter([(
                KeyAlgorithmType::Eddsa,
                Arc::new(Eddsa) as _,
            )])));

        let key_verification = KeyVerification {
            did_method_provider: Arc::new(did_method_provider),
            key_algorithm_provider,
            key_role: KeyRole::Authentication,
            certificate_validator: Arc::new(MockCertificateValidator::default()),
        };

        Box::new(key_verification)
    }

    fn auth_fn() -> Box<dyn SignatureProvider> {
        let key_algorithm = Eddsa;
        let key_handle = key_algorithm
            .reconstruct_key(&public_key(), Some(private_key().into()), None)
            .unwrap();

        let provider = SignatureProviderImpl {
            key: Key {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: key_handle.public_key_as_raw(),
                name: "test".to_string(),
                key_reference: vec![],
                storage_type: "test".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
            key_handle,
            jwk_key_id: None,
            key_algorithm_provider: Arc::new(KeyAlgorithmProviderImpl::new(HashMap::from_iter([
                (KeyAlgorithmType::Eddsa, Arc::new(key_algorithm) as _),
            ]))),
        };

        Box::new(provider)
    }

    fn did_key() -> DidValue {
        let key_algorithm = Eddsa;
        let key_handle = key_algorithm
            .reconstruct_key(&public_key(), None, None)
            .unwrap();

        format!("did:key:{}", key_handle.public_key_as_multibase().unwrap())
            .parse()
            .unwrap()
    }

    fn pk_jwk() -> PublicKeyJwk {
        let key_algorithm = Eddsa;
        let key_handle = key_algorithm
            .reconstruct_key(&public_key(), None, None)
            .unwrap();

        key_handle.public_key_as_jwk().unwrap()
    }

    fn public_key() -> Vec<u8> {
        hex::decode("c213ff6fb1a57a0c7353443527a7cd5775c3c58b8f32476dee8200fb5767904d").unwrap()
    }

    fn private_key() -> Vec<u8> {
        hex::decode("8a678952e56a863069881cc68f4c54e62e4da470b1c836d712945640354d4f90c213ff6fb1a57a0c7353443527a7cd5775c3c58b8f32476dee8200fb5767904d").unwrap()
    }
}
