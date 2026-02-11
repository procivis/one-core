use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;

use crate::error::ContextWithErrorCode;
use crate::proto::jwt::model::{DecomposedJwt, JWTPayload};
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, PublicKeySource, TokenVerifier,
};
use crate::service::wallet_provider::dto::WalletUnitAttestationClaims;

const JWT_PROOF_TYPE: &str = "openid4vci-proof+jwt";

pub(crate) struct OpenID4VCIProofJWTFormatter;

#[derive(Debug, Default, Deserialize)]
struct ProofOfPossession {
    pub nonce: Option<String>,
}

#[derive(Debug)]
pub(crate) enum OpenID4VCIProofHolderBinding {
    Did { did: DidValue, key_id: String },
    Jwk(PublicJwk),
}

#[derive(Debug)]
pub(crate) struct OpenID4VCIVerifiedProof {
    pub holder_binding: OpenID4VCIProofHolderBinding,
    pub nonce: Option<String>,
    pub key_attestation: Option<String>,
}

impl OpenID4VCIProofJWTFormatter {
    pub(crate) async fn verify_proof(
        jwt: &str,
        verifier: &dyn TokenVerifier,
    ) -> Result<OpenID4VCIVerifiedProof, FormatterError> {
        let proof_jwt: DecomposedJwt<ProofOfPossession> =
            Jwt::decompose_token(jwt).error_while("parsing proof token")?;

        match proof_jwt.header.r#type.as_deref() {
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

        let (holder_binding, public_key_source) = match (
            proof_jwt.header.key_id.as_ref(),
            proof_jwt.header.jwk.as_ref(),
        ) {
            (Some(_), Some(_)) => {
                return Err(FormatterError::CouldNotVerify(
                    "Only kid or embedded jwk allowed in proof.jwt but not both".to_string(),
                ));
            }
            (None, None) => {
                return Err(FormatterError::CouldNotVerify(
                    "Missing kid or jwk".to_string(),
                ));
            }
            (None, Some(jwk)) => (
                OpenID4VCIProofHolderBinding::Jwk(jwk.to_owned()),
                jwk.into(),
            ),
            (Some(key_id), None) => {
                if key_id.starts_with("did:") {
                    let (did, fragment) = match key_id.find('#') {
                        // key_id is verificationMethod id
                        Some(idx) => (&key_id[..idx], Some(key_id.as_str())),
                        None => (key_id.as_str(), None),
                    };

                    let did: DidValue = did
                        .parse()
                        .map_err(|e| FormatterError::CouldNotVerify(format!("Invalid did: {e}")))?;

                    (
                        OpenID4VCIProofHolderBinding::Did {
                            did: did.clone(),
                            key_id: key_id.clone(),
                        },
                        PublicKeySource::Did {
                            did: Cow::Owned(did),
                            key_id: fragment,
                        },
                    )
                } else if let Some(key_attestation_jwt) = &proof_jwt.header.key_attestation {
                    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.1-10
                    // public key is contained inside the key attestation
                    let attested_key_index: usize = key_id.parse().map_err(|e| {
                        FormatterError::CouldNotVerify(format!("Invalid proof JWT kid: {e}"))
                    })?;

                    let wua =
                        Jwt::<WalletUnitAttestationClaims>::decompose_token(key_attestation_jwt)
                            .error_while("parsing WUA token")?;

                    let attested_key = wua
                        .payload
                        .custom
                        .attested_keys
                        .get(attested_key_index)
                        .ok_or(FormatterError::CouldNotVerify(
                          format!("Invalid key attestation: missing attested key, index: {attested_key_index}")
                        ))?
                        .to_owned();

                    (
                        OpenID4VCIProofHolderBinding::Jwk(attested_key.to_owned()),
                        PublicKeySource::Jwk {
                            jwk: Cow::Owned(attested_key),
                        },
                    )
                } else {
                    return Err(FormatterError::CouldNotVerify(format!(
                        "Invalid proof JWT kid: `{key_id}`"
                    )));
                }
            }
        };

        proof_jwt
            .verify_signature(public_key_source, verifier)
            .await
            .error_while("validating proof token")?;

        Ok(OpenID4VCIVerifiedProof {
            holder_binding,
            nonce: proof_jwt.payload.custom.nonce,
            key_attestation: proof_jwt.header.key_attestation,
        })
    }

    pub(crate) async fn format_proof(
        issuer_url: String,
        jwk: Option<PublicJwk>,
        nonce: Option<String>,
        key_attestation: Option<String>,
        auth_fn: AuthenticationFn,
        client_id: Option<String>,
    ) -> Result<String, FormatterError> {
        #[derive(Serialize)]
        struct NonceClaim {
            nonce: String,
        }

        let custom = nonce.map(|nonce| NonceClaim { nonce });
        let payload = JWTPayload {
            issuer: client_id,
            audience: Some(vec![issuer_url]),
            custom,
            issued_at: Some(OffsetDateTime::now_utc()),
            ..Default::default()
        };

        let key_id = match jwk {
            Some(_) => None,
            None => auth_fn.get_key_id(),
        };
        let jwk = jwk.map(JwtPublicKeyInfo::Jwk);

        let jwt = Jwt::new_with_attestation(
            JWT_PROOF_TYPE.to_string(),
            auth_fn.jose_alg().ok_or(FormatterError::CouldNotFormat(
                "Invalid key algorithm".to_string(),
            ))?,
            key_id,
            jwk,
            key_attestation,
            payload,
        );

        Ok(jwt
            .tokenize(Some(&*auth_fn))
            .await
            .error_while("creating proof token")?)
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use super::*;
    use crate::config::core_config::KeyAlgorithmType;
    use crate::model::did::KeyRole;
    use crate::model::key::Key;
    use crate::proto::certificate_validator::MockCertificateValidator;
    use crate::proto::key_verification::KeyVerification;
    use crate::provider::credential_formatter::model::SignatureProvider;
    use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
    use crate::provider::did_method::provider::MockDidMethodProvider;
    use crate::provider::key_algorithm::KeyAlgorithm;
    use crate::provider::key_algorithm::eddsa::Eddsa;
    use crate::provider::key_algorithm::provider::{MockKeyAlgorithmProvider, ParsedKey};
    use crate::provider::key_storage::provider::SignatureProviderImpl;

    #[tokio::test]
    async fn test_format_then_verify_proof_with_holder_key_id() {
        let holder_key_id = did_key();
        let auth_fn = auth_fn(Some(format!("{holder_key_id}#key-1")));

        let proof = OpenID4VCIProofJWTFormatter::format_proof(
            "https://example.com".to_string(),
            None,
            None,
            None,
            auth_fn,
            None,
        )
        .await
        .unwrap();

        let OpenID4VCIVerifiedProof {
            key_attestation, ..
        } = OpenID4VCIProofJWTFormatter::verify_proof(&proof, verifier().as_ref())
            .await
            .unwrap();
        assert_eq!(key_attestation, None);
    }

    #[tokio::test]
    async fn test_format_then_verify_proof_with_jwk() {
        let auth_fn = auth_fn(None);
        let jwk = pk_jwk();

        let proof = OpenID4VCIProofJWTFormatter::format_proof(
            "https://example.com".to_string(),
            Some(jwk),
            Some("nonce".to_string()),
            None,
            auth_fn,
            None,
        )
        .await
        .unwrap();

        let OpenID4VCIVerifiedProof {
            nonce,
            key_attestation,
            ..
        } = OpenID4VCIProofJWTFormatter::verify_proof(&proof, verifier().as_ref())
            .await
            .unwrap();
        assert_eq!(nonce, Some("nonce".to_string()));
        assert_eq!(key_attestation, None);
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

        let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
        key_algorithm_provider
            .expect_key_algorithm_from_type()
            .returning(|_| Some(Arc::new(Eddsa)));
        key_algorithm_provider
            .expect_key_algorithm_from_jose_alg()
            .returning(|_| Some((KeyAlgorithmType::Eddsa, Arc::new(Eddsa))));
        key_algorithm_provider.expect_parse_jwk().returning(|key| {
            Ok(ParsedKey {
                algorithm_type: KeyAlgorithmType::Eddsa,
                key: Eddsa.parse_jwk(key).unwrap(),
            })
        });

        let key_verification = KeyVerification {
            did_method_provider: Arc::new(did_method_provider),
            key_algorithm_provider: Arc::new(key_algorithm_provider),
            key_role: KeyRole::Authentication,
            certificate_validator: Arc::new(MockCertificateValidator::default()),
        };

        Box::new(key_verification)
    }

    fn auth_fn(key_id: Option<String>) -> Box<dyn SignatureProvider> {
        let key_algorithm = Eddsa;
        let key_handle = key_algorithm
            .reconstruct_key(&public_key(), Some(private_key().into()), None)
            .unwrap();

        let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
        key_algorithm_provider
            .expect_key_algorithm_from_type()
            .returning(|_| Some(Arc::new(Eddsa)));

        let provider = SignatureProviderImpl {
            key: Key {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: key_handle.public_key_as_raw(),
                name: "test".to_string(),
                key_reference: None,
                storage_type: "test".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: None,
            },
            key_handle,
            jwk_key_id: key_id,
            key_algorithm_provider: Arc::new(key_algorithm_provider),
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

    fn pk_jwk() -> PublicJwk {
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
