use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::SignerError;
use shared_types::DidValue;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::did::KeyRole;
use crate::provider::credential_formatter::model::{PublicKeySource, TokenVerifier};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::certificate::validator::{CertificateValidator, ParsedCertificate};
use crate::util::x509::x5c_into_pem_chain;

#[derive(Clone)]
pub struct KeyVerification {
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    pub certificate_validator: Arc<dyn CertificateValidator>,
    pub key_role: KeyRole,
}

impl KeyVerification {
    async fn public_key_from_did(
        &self,
        issuer_did_value: &DidValue,
        issuer_key_id: Option<&str>,
        algorithm: KeyAlgorithmType,
    ) -> Result<KeyHandle, SignerError> {
        let did_document = self
            .did_method_provider
            .resolve(issuer_did_value)
            .await
            .map_err(|e| SignerError::CouldNotVerify(e.to_string()))?;

        let key_id_list = match &self.key_role {
            KeyRole::Authentication => did_document.authentication,
            KeyRole::AssertionMethod => did_document.assertion_method,
            KeyRole::KeyAgreement => did_document.key_agreement,
            KeyRole::CapabilityInvocation => did_document.capability_invocation,
            KeyRole::CapabilityDelegation => did_document.capability_delegation,
            KeyRole::UpdateKey => None,
        }
        .ok_or(SignerError::MissingKey)?;

        let method_id = if let Some(issuer_key_id) = issuer_key_id {
            issuer_key_id
        } else {
            key_id_list.first().ok_or(SignerError::MissingKey)?
        };

        tracing::debug!("Verification method_id: {method_id}");
        let method = did_document
            .verification_method
            .into_iter()
            .find(|method| method.id == method_id)
            .ok_or(SignerError::MissingKey)?;
        let alg = self
            .key_algorithm_provider
            .key_algorithm_from_type(algorithm)
            .ok_or(SignerError::CouldNotVerify(format!(
                "Invalid algorithm: {algorithm}"
            )))?;

        let public_key = alg
            .parse_jwk(&method.public_key_jwk)
            .map_err(|e| SignerError::CouldNotVerify(e.to_string()))?;
        Ok(public_key)
    }

    async fn public_key_from_cert(&self, x5c: &[String]) -> Result<KeyHandle, SignerError> {
        let pem_chain = x5c_into_pem_chain(x5c).map_err(|err| {
            SignerError::CouldNotVerify(format!("failed to parse x5c header param: {err}"))
        })?;

        let ParsedCertificate { public_key, .. } = self
            .certificate_validator
            .parse_pem_chain(pem_chain.as_bytes(), true)
            .await
            .map_err(|err| {
                SignerError::CouldNotVerify(format!("failed to parse certificate chain: {err}"))
            })?;
        Ok(public_key)
    }
}

#[async_trait]
impl TokenVerifier for KeyVerification {
    async fn verify<'a>(
        &self,
        public_key_source: PublicKeySource<'a>,
        algorithm: KeyAlgorithmType,
        token: &'a [u8],
        signature: &'a [u8],
    ) -> Result<(), SignerError> {
        let public_key = match public_key_source {
            PublicKeySource::Did { did, key_id } => {
                self.public_key_from_did(&did, key_id, algorithm).await
            }
            PublicKeySource::X5c { x5c, .. } => self.public_key_from_cert(x5c).await,
            PublicKeySource::Jwk { jwk } => {
                let alg = self
                    .key_algorithm_provider
                    .key_algorithm_from_type(algorithm)
                    .ok_or(SignerError::CouldNotVerify(format!(
                        "Invalid algorithm: {algorithm}"
                    )))?;
                alg.parse_jwk(&jwk)
                    .map_err(|e| SignerError::CouldNotVerify(e.to_string()))
            }
        }?;
        public_key.verify(token, signature)
    }

    fn key_algorithm_provider(&self) -> &dyn KeyAlgorithmProvider {
        &*self.key_algorithm_provider
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;

    use mockall::predicate::*;
    use serde_json::json;

    use super::*;
    use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
    use crate::provider::did_method::error::DidMethodProviderError;
    use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
    use crate::provider::did_method::provider::MockDidMethodProvider;
    use crate::provider::key_algorithm::MockKeyAlgorithm;
    use crate::provider::key_algorithm::key::{
        KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
    };
    use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
    use crate::service::certificate::validator::MockCertificateValidator;

    fn get_dummy_did_document() -> DidDocument {
        DidDocument {
            context: json!(["https://www.w3.org/ns/did/v1"]),
            id: "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".parse().unwrap(),
            verification_method: vec![
                DidVerificationMethod {
                    id: "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned(),
                    r#type: "JsonWebKey2020".to_owned(),
                    controller: "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned(),
                    public_key_jwk: PublicKeyJwk::Ec(
                        PublicKeyJwkEllipticData {
                            r#use: None,
                            kid: None,
                            crv: "P-256".to_owned(),
                            x: "AjDk2GBBiI_M6HvEmgfzXiVhJCWiVFqvoItknJgc-oEE".to_owned(),
                            y: None,
                        },
                    ),
                },
            ],
            authentication: Some(vec!["did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned()]),
            assertion_method: Some(vec!["did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned()]),
            key_agreement: Some(vec!["did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned()]),
            capability_invocation: Some(vec!["did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned()]),
            capability_delegation: Some(vec!["did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned()]),
            also_known_as: None,
            service: None,
        }
    }

    #[tokio::test]
    async fn test_verify_success() {
        let mut did_method_provider = MockDidMethodProvider::default();
        did_method_provider
            .expect_resolve()
            .once()
            .returning(|_| Ok(get_dummy_did_document()));

        let mut key_alg = MockKeyAlgorithm::default();
        key_alg.expect_parse_jwk().return_once(|_| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle
                .expect_as_raw()
                .return_once(|| b"public_key".to_vec());
            key_handle
                .expect_verify()
                .with(eq("token".as_bytes()), eq(b"signature".as_slice()))
                .once()
                .returning(|_, _| Ok(()));

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

        let key_alg = Arc::new(key_alg);

        let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
        key_algorithm_provider
            .expect_key_algorithm_from_type()
            .once()
            .withf(move |alg| {
                assert_eq!(*alg, KeyAlgorithmType::Ecdsa);
                true
            })
            .returning(move |_| Some(key_alg.clone()));

        let verification = KeyVerification {
            key_algorithm_provider: Arc::new(key_algorithm_provider),
            did_method_provider: Arc::new(did_method_provider),
            certificate_validator: Arc::new(MockCertificateValidator::default()),
            key_role: KeyRole::Authentication,
        };

        let did_value = "did:example:123".parse().unwrap();
        let params = PublicKeySource::Did {
            did: Cow::Owned(did_value),
            key_id: None,
        };
        let result = verification
            .verify(
                params,
                KeyAlgorithmType::Ecdsa,
                "token".as_bytes(),
                b"signature",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_did_resolution_failed() {
        let mut did_method_provider = MockDidMethodProvider::default();
        did_method_provider
            .expect_resolve()
            .once()
            .returning(|_| Err(DidMethodProviderError::Other("test-error".to_string())));

        let key_algorithm_provider = MockKeyAlgorithmProvider::default();

        let verification = KeyVerification {
            key_algorithm_provider: Arc::new(key_algorithm_provider),
            did_method_provider: Arc::new(did_method_provider),
            certificate_validator: Arc::new(MockCertificateValidator::default()),
            key_role: KeyRole::Authentication,
        };

        let did_value = "did:example:123".parse().unwrap();
        let params = PublicKeySource::Did {
            did: Cow::Owned(did_value),
            key_id: None,
        };
        let result = verification
            .verify(
                params,
                KeyAlgorithmType::Ecdsa,
                "token".as_bytes(),
                b"signature",
            )
            .await;
        assert!(matches!(result, Err(SignerError::CouldNotVerify(_))));
    }

    #[tokio::test]
    async fn test_verify_signature_verification_fails() {
        let mut did_method_provider = MockDidMethodProvider::default();
        did_method_provider
            .expect_resolve()
            .once()
            .returning(|_| Ok(get_dummy_did_document()));

        let mut key_alg = MockKeyAlgorithm::default();
        key_alg.expect_parse_jwk().return_once(|_| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle
                .expect_as_raw()
                .return_once(|| b"public_key".to_vec());
            key_handle
                .expect_verify()
                .with(eq("token".as_bytes()), eq(b"signature".as_slice()))
                .once()
                .returning(|_, _| Err(SignerError::InvalidSignature));

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

        let key_alg = Arc::new(key_alg);

        let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
        key_algorithm_provider
            .expect_key_algorithm_from_type()
            .once()
            .withf(move |alg| {
                assert_eq!(*alg, KeyAlgorithmType::Ecdsa);
                true
            })
            .returning(move |_| Some(key_alg.clone()));

        let verification = KeyVerification {
            key_algorithm_provider: Arc::new(key_algorithm_provider),
            did_method_provider: Arc::new(did_method_provider),
            certificate_validator: Arc::new(MockCertificateValidator::default()),
            key_role: KeyRole::Authentication,
        };

        let did_value = "did:example:123".parse().unwrap();
        let params = PublicKeySource::Did {
            did: Cow::Owned(did_value),
            key_id: None,
        };
        let result = verification
            .verify(
                params,
                KeyAlgorithmType::Ecdsa,
                "token".as_bytes(),
                b"signature",
            )
            .await;
        assert!(matches!(result, Err(SignerError::InvalidSignature)));
    }
}
