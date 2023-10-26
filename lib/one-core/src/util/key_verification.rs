use crate::{
    common_mapper::get_algorithm_from_key_algorithm,
    config::data_structure::CoreConfig,
    crypto::{signer::SignerError, Crypto},
    model::did::KeyRole,
    provider::{credential_formatter::jwt::TokenVerifier, did_method::provider::DidMethodProvider},
};
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct KeyVerification {
    pub config: Arc<CoreConfig>,
    pub crypto: Arc<Crypto>,
    pub did_method_provider: Arc<dyn DidMethodProvider + Send + Sync>,
}

#[async_trait]
impl TokenVerifier for KeyVerification {
    async fn verify<'a>(
        &self,
        issuer_did_value: &'a str,
        algorithm: &'a str,
        token: &'a str,
        signature: &'a [u8],
    ) -> Result<(), SignerError> {
        let algorithm = get_algorithm_from_key_algorithm(algorithm, &self.config)
            .map_err(|_| SignerError::CouldNotSign)?;

        let signer = self
            .crypto
            .signers
            .get(&algorithm)
            .ok_or(SignerError::MissingAlgorithm(algorithm))?;

        let did = self
            .did_method_provider
            .resolve(issuer_did_value)
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
        crypto::signer::{MockSigner, Signer},
        model::{
            did::{Did, DidType, RelatedKey},
            key::Key,
        },
        provider::did_method::provider::MockDidMethodProvider,
        service::{error::ServiceError, test_utilities::generic_config},
    };
    use mockall::predicate::*;
    use std::collections::HashMap;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn get_dummy_did() -> Did {
        Did {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            name: "issuer_did".to_string(),
            did: "issuer_did_value".to_string(),
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
            .times(1)
            .returning(|_, _, _| Ok(()));

        let verification = KeyVerification {
            config: Arc::new(generic_config()),
            crypto: Arc::new(Crypto {
                signers: HashMap::from_iter([(
                    "Ed25519".to_string(),
                    Arc::new(signer) as Arc<dyn Signer + Send + Sync>,
                )]),
                ..Default::default()
            }),
            did_method_provider: Arc::new(did_method_provider),
        };

        let result = verification
            .verify("issuer_did_value", "EDDSA", "token", b"signature")
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

        let verification = KeyVerification {
            config: Arc::new(generic_config()),
            crypto: Arc::new(Crypto {
                signers: HashMap::from_iter([(
                    "Ed25519".to_string(),
                    Arc::new(MockSigner::default()) as Arc<dyn Signer + Send + Sync>,
                )]),
                ..Default::default()
            }),
            did_method_provider: Arc::new(did_method_provider),
        };

        let result = verification
            .verify("issuer_did_value", "EDDSA", "token", b"signature")
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

        let verification = KeyVerification {
            config: Arc::new(generic_config()),
            crypto: Arc::new(Crypto {
                signers: HashMap::from_iter([(
                    "Ed25519".to_string(),
                    Arc::new(signer) as Arc<dyn Signer + Send + Sync>,
                )]),
                ..Default::default()
            }),
            did_method_provider: Arc::new(did_method_provider),
        };

        let result = verification
            .verify("issuer_did_value", "EDDSA", "token", b"signature")
            .await;
        assert!(matches!(result, Err(SignerError::InvalidSignature)));
    }
}
