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
    pub did_method_provider: Arc<dyn DidMethodProvider + Send + Sync>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
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
        let signer = self
            .key_algorithm_provider
            .get_signer(algorithm)
            .map_err(|e| SignerError::CouldNotVerify(e.to_string()))?;

        let did = self
            .did_method_provider
            .resolve(
                &issuer_did_value
                    .ok_or(SignerError::CouldNotVerify("Missing issuer".to_string()))?,
            )
            .await
            .map_err(|e| SignerError::CouldNotVerify(e.to_string()))?;

        let public_key = did
            .keys
            .ok_or(SignerError::MissingKey)?
            .iter()
            .find(|key| key.role == KeyRole::AssertionMethod)
            .ok_or(SignerError::MissingKey)?
            .key
            .public_key
            .to_owned();

        signer.verify(token, signature, &public_key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        crypto::signer::MockSigner,
        model::{
            did::{Did, DidType, RelatedKey},
            key::Key,
        },
        provider::{
            did_method::provider::MockDidMethodProvider,
            key_algorithm::provider::MockKeyAlgorithmProvider,
        },
        service::error::ServiceError,
    };
    use mockall::predicate::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn get_dummy_did() -> Did {
        Did {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "issuer_did".to_string(),
            did: "issuer_did_value".parse().unwrap(),
            did_type: DidType::Remote,
            did_method: "KEY".to_string(),
            keys: Some(vec![RelatedKey {
                role: KeyRole::AssertionMethod,
                key: Key {
                    id: Uuid::new_v4(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    public_key: b"public_key".to_vec(),
                    name: "issuer_key".to_string(),
                    private_key: vec![],
                    storage_type: "EPHEMERAL".to_string(),
                    key_type: "EDDSA".to_string(),
                    organisation: None,
                },
            }]),
            organisation: None,
        }
    }

    #[tokio::test]
    async fn test_verify_success() {
        let mut did_method_provider = MockDidMethodProvider::default();
        did_method_provider
            .expect_resolve()
            .times(1)
            .returning(|_| Ok(get_dummy_did()));

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

        let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
        key_algorithm_provider
            .expect_get_signer()
            .once()
            .withf(move |alg| {
                assert_eq!(alg, "EDDSA");
                true
            })
            .returning(move |_| Ok(signer.clone()));

        let verification = KeyVerification {
            key_algorithm_provider: Arc::new(key_algorithm_provider),
            did_method_provider: Arc::new(did_method_provider),
        };

        let result = verification
            .verify(
                Some("issuer_did_value".parse().unwrap()),
                "EDDSA",
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
            .times(1)
            .returning(|_| Err(ServiceError::Other("test-error".to_string())));

        let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
        key_algorithm_provider
            .expect_get_signer()
            .once()
            .withf(move |alg| {
                assert_eq!(alg, "EDDSA");
                true
            })
            .returning(move |_| Ok(Arc::new(MockSigner::default())));

        let verification = KeyVerification {
            key_algorithm_provider: Arc::new(key_algorithm_provider),
            did_method_provider: Arc::new(did_method_provider),
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
            .times(1)
            .returning(|_| Ok(get_dummy_did()));

        let mut signer = MockSigner::default();
        signer
            .expect_verify()
            .returning(|_, _, _| Err(SignerError::InvalidSignature));

        let signer = Arc::new(signer);

        let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
        key_algorithm_provider
            .expect_get_signer()
            .once()
            .withf(move |alg| {
                assert_eq!(alg, "EDDSA");
                true
            })
            .returning(move |_| Ok(signer.clone()));

        let verification = KeyVerification {
            key_algorithm_provider: Arc::new(key_algorithm_provider),
            did_method_provider: Arc::new(did_method_provider),
        };

        let result = verification
            .verify(
                Some("issuer_did_value".parse().unwrap()),
                "EDDSA",
                "token",
                b"signature",
            )
            .await;
        assert!(matches!(result, Err(SignerError::InvalidSignature)));
    }
}
