use crate::{
    crypto::signer::error::SignerError,
    model::did::KeyRole,
    provider::{
        credential_formatter::TokenVerifier, did_method::provider::DidMethodProvider,
        key_algorithm::provider::KeyAlgorithmProvider,
    },
};
use async_trait::async_trait;
use shared_types::DidValue;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct KeyVerification {
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    pub key_role: KeyRole,
}

#[async_trait]
impl TokenVerifier for KeyVerification {
    async fn verify<'a>(
        &self,
        issuer_did_value: Option<DidValue>,
        algorithm: &'a str,
        token: &'a str,
        signature: &'a [u8],
    ) -> Result<(), SignerError> {
        let did_document = self
            .did_method_provider
            .resolve(
                &issuer_did_value
                    .ok_or(SignerError::CouldNotVerify("Missing issuer".to_string()))?,
            )
            .await
            .map_err(|e| SignerError::CouldNotVerify(e.to_string()))?;

        let key_id_list = match &self.key_role {
            KeyRole::Authentication => did_document.authentication,
            KeyRole::AssertionMethod => did_document.assertion_method,
            KeyRole::KeyAgreement => did_document.key_agreement,
            KeyRole::CapabilityInvocation => did_document.capability_invocation,
            KeyRole::CapabilityDelegation => did_document.capability_delegation,
        }
        .ok_or(SignerError::MissingKey)?;

        let method_id = key_id_list.first().ok_or(SignerError::MissingKey)?;

        let method = did_document
            .verification_method
            .iter()
            .find(|method| &method.id == method_id)
            .ok_or(SignerError::MissingKey)?;

        let alg = self
            .key_algorithm_provider
            .get_key_algorithm(algorithm)
            .ok_or(SignerError::CouldNotVerify(format!(
                "Invalid algorithm: {algorithm}"
            )))?;

        let public_key = alg
            .jwk_to_bytes(&method.public_key_jwk)
            .map_err(|e| SignerError::CouldNotVerify(e.to_string()))?;

        let signer = self
            .key_algorithm_provider
            .get_signer(algorithm)
            .map_err(|e| SignerError::CouldNotVerify(e.to_string()))?;

        signer.verify(token, signature, &public_key)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use crate::provider::did_method::dto::{
        DidDocumentDTO, DidVerificationMethodDTO, PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO,
    };
    use crate::provider::key_algorithm::MockKeyAlgorithm;
    use crate::{
        crypto::signer::MockSigner,
        provider::{
            did_method::provider::MockDidMethodProvider,
            key_algorithm::provider::MockKeyAlgorithmProvider,
        },
        service::error::ServiceError,
    };
    use mockall::predicate::*;
    use serde_json::json;

    fn get_dummy_did_document() -> DidDocumentDTO {
        DidDocumentDTO {
            context: json!(["https://www.w3.org/ns/did/v1"]),
            id: DidValue::from_str("did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb").unwrap(),
            verification_method: vec![
                DidVerificationMethodDTO {
                    id: "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb#zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned(),
                    r#type: "JsonWebKey2020".to_owned(),
                    controller: "did:key:zDnaeTiq1PdzvZXUaMdezchcMJQpBdH2VN4pgrrEhMCCbmwSb".to_owned(),
                    public_key_jwk: PublicKeyJwkDTO::Ec(
                        PublicKeyJwkEllipticDataDTO {
                            r#use: None,
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
            rest: Default::default(),
        }
    }

    #[tokio::test]
    async fn test_verify_success() {
        let mut did_method_provider = MockDidMethodProvider::default();
        did_method_provider
            .expect_resolve()
            .once()
            .returning(|_| Ok(get_dummy_did_document()));

        let mut signer = MockSigner::default();
        signer
            .expect_verify()
            .with(
                eq("token"),
                eq(b"signature".as_slice()),
                eq(b"public_key".as_slice()),
            )
            .once()
            .returning(|_, _, _| Ok(()));

        let signer = Arc::new(signer);

        let mut key_alg = MockKeyAlgorithm::default();
        key_alg
            .expect_jwk_to_bytes()
            .once()
            .returning(|_| Ok(b"public_key".to_vec()));

        let key_alg = Arc::new(key_alg);

        let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
        key_algorithm_provider
            .expect_get_signer()
            .once()
            .withf(move |alg| {
                assert_eq!(alg, "ES256");
                true
            })
            .returning(move |_| Ok(signer.clone()));

        key_algorithm_provider
            .expect_get_key_algorithm()
            .once()
            .withf(move |alg| {
                assert_eq!(alg, "ES256");
                true
            })
            .returning(move |_| Some(key_alg.clone()));

        let verification = KeyVerification {
            key_algorithm_provider: Arc::new(key_algorithm_provider),
            did_method_provider: Arc::new(did_method_provider),
            key_role: KeyRole::Authentication,
        };

        let result = verification
            .verify(
                Some("issuer_did_value".parse().unwrap()),
                "ES256",
                "token",
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
            .returning(|_| Err(ServiceError::Other("test-error".to_string())));

        let key_algorithm_provider = MockKeyAlgorithmProvider::default();

        let verification = KeyVerification {
            key_algorithm_provider: Arc::new(key_algorithm_provider),
            did_method_provider: Arc::new(did_method_provider),
            key_role: KeyRole::Authentication,
        };

        let result = verification
            .verify(
                Some("issuer_did_value".parse().unwrap()),
                "EDDSA",
                "token",
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

        let mut signer = MockSigner::default();
        signer
            .expect_verify()
            .returning(|_, _, _| Err(SignerError::InvalidSignature));

        let signer = Arc::new(signer);

        let mut key_alg = MockKeyAlgorithm::default();
        key_alg
            .expect_jwk_to_bytes()
            .once()
            .returning(|_| Ok(b"public_key".to_vec()));

        let key_alg = Arc::new(key_alg);

        let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
        key_algorithm_provider
            .expect_get_signer()
            .once()
            .withf(move |alg| {
                assert_eq!(alg, "ES256");
                true
            })
            .returning(move |_| Ok(signer.clone()));

        key_algorithm_provider
            .expect_get_key_algorithm()
            .once()
            .withf(move |alg| {
                assert_eq!(alg, "ES256");
                true
            })
            .returning(move |_| Some(key_alg.clone()));

        let verification = KeyVerification {
            key_algorithm_provider: Arc::new(key_algorithm_provider),
            did_method_provider: Arc::new(did_method_provider),
            key_role: KeyRole::Authentication,
        };

        let result = verification
            .verify(
                Some("issuer_did_value".parse().unwrap()),
                "ES256",
                "token",
                b"signature",
            )
            .await;
        assert!(matches!(result, Err(SignerError::InvalidSignature)));
    }
}
