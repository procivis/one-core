use super::InternalKeyProvider;
use crate::crypto::signer::{MockSigner, Signer};
use crate::model::key::Key;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_algorithm::{GeneratedKey, KeyAlgorithm, MockKeyAlgorithm};
use crate::provider::key_storage::internal::Params;
use crate::provider::key_storage::KeyStorage;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

#[tokio::test]
async fn test_internal_generate() {
    let mut mock_key_algorithm = MockKeyAlgorithm::default();
    mock_key_algorithm
        .expect_generate_key_pair()
        .times(1)
        .returning(|| GeneratedKey {
            public: vec![1],
            private: vec![1, 2, 3],
        });

    let arc: Arc<dyn KeyAlgorithm + Send + Sync> = Arc::new(mock_key_algorithm);

    let mut mock_key_algorithm_provider = MockKeyAlgorithmProvider::default();
    mock_key_algorithm_provider
        .expect_get_key_algorithm()
        .times(1)
        .returning(move |_| Ok(arc.clone()));

    let provider = InternalKeyProvider {
        key_algorithm_provider: Arc::new(mock_key_algorithm_provider),
        params: Params { encryption: None },
    };

    let result = provider.generate("").await.unwrap();
    assert_eq!(3, result.private.len());
}

#[tokio::test]
async fn test_internal_generate_with_encryption() {
    let mut mock_key_algorithm = MockKeyAlgorithm::default();
    mock_key_algorithm
        .expect_generate_key_pair()
        .times(1)
        .returning(|| GeneratedKey {
            public: vec![1],
            private: vec![1, 2, 3],
        });

    let arc: Arc<dyn KeyAlgorithm + Send + Sync> = Arc::new(mock_key_algorithm);

    let mut mock_key_algorithm_provider = MockKeyAlgorithmProvider::default();
    mock_key_algorithm_provider
        .expect_get_key_algorithm()
        .times(1)
        .returning(move |_| Ok(arc.clone()));

    let provider = InternalKeyProvider {
        key_algorithm_provider: Arc::new(mock_key_algorithm_provider),
        params: Params {
            encryption: Some("password".to_string()),
        },
    };

    let result = provider.generate("").await.unwrap();
    assert!(result.private.starts_with("age".as_bytes()));
}

#[tokio::test]
async fn test_internal_sign_with_encryption() {
    let expected_signed_response = vec![1u8];

    let mut mock_key_algorithm = MockKeyAlgorithm::default();
    mock_key_algorithm
        .expect_generate_key_pair()
        .times(1)
        .returning(|| GeneratedKey {
            public: vec![1],
            private: vec![1, 2, 3],
        });
    let mut mock_signer = MockSigner::default();
    mock_signer
        .expect_sign()
        .times(1)
        .returning(move |_, _, _| Ok(expected_signed_response.clone()));

    let arc_key_algorithm: Arc<dyn KeyAlgorithm + Send + Sync> = Arc::new(mock_key_algorithm);
    let arc_signer: Arc<dyn Signer + Send + Sync> = Arc::new(mock_signer);

    let mut mock_key_algorithm_provider = MockKeyAlgorithmProvider::default();
    mock_key_algorithm_provider
        .expect_get_key_algorithm()
        .times(1)
        .returning(move |_| Ok(arc_key_algorithm.clone()));
    mock_key_algorithm_provider
        .expect_get_signer()
        .times(1)
        .returning(move |_| Ok(arc_signer.clone()));

    let provider = InternalKeyProvider {
        key_algorithm_provider: Arc::new(mock_key_algorithm_provider),
        params: Params {
            encryption: Some("password".to_string()),
        },
    };

    let generated_key = provider.generate("").await.unwrap();

    let key = Key {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: generated_key.public,
        name: "".to_string(),
        private_key: generated_key.private,
        storage_type: "".to_string(),
        key_type: "".to_string(),
        organisation: None,
    };

    provider.sign(&key, "message").await.unwrap();
}
