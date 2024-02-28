use super::InternalKeyProvider;
use crate::crypto::signer::MockSigner;
use crate::model::key::Key;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_algorithm::{GeneratedKey, MockKeyAlgorithm};
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

    let arc = Arc::new(mock_key_algorithm);

    let mut mock_key_algorithm_provider = MockKeyAlgorithmProvider::default();
    mock_key_algorithm_provider
        .expect_get_key_algorithm()
        .times(1)
        .returning(move |_| Some(arc.clone()));

    let provider = InternalKeyProvider::new(
        Arc::new(mock_key_algorithm_provider),
        Params { encryption: None },
    );

    let result = provider.generate(&Uuid::new_v4().into(), "").await.unwrap();
    assert_eq!(3, result.key_reference.len());
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

    let arc = Arc::new(mock_key_algorithm);

    let mut mock_key_algorithm_provider = MockKeyAlgorithmProvider::default();
    mock_key_algorithm_provider
        .expect_get_key_algorithm()
        .times(1)
        .returning(move |_| Some(arc.clone()));

    let provider = InternalKeyProvider::new(
        Arc::new(mock_key_algorithm_provider),
        Params {
            encryption: Some("password".to_string()),
        },
    );

    let result = provider.generate(&Uuid::new_v4().into(), "").await.unwrap();
    assert_eq!(result.key_reference.len(), 39);
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

    let arc_key_algorithm = Arc::new(mock_key_algorithm);
    let arc_signer = Arc::new(mock_signer);

    let mut mock_key_algorithm_provider = MockKeyAlgorithmProvider::default();
    mock_key_algorithm_provider
        .expect_get_key_algorithm()
        .times(1)
        .returning(move |_| Some(arc_key_algorithm.clone()));
    mock_key_algorithm_provider
        .expect_get_signer()
        .times(1)
        .returning(move |_| Ok(arc_signer.clone()));

    let provider = InternalKeyProvider::new(
        Arc::new(mock_key_algorithm_provider),
        Params {
            encryption: Some("password".to_string()),
        },
    );

    let generated_key = provider.generate(&Uuid::new_v4().into(), "").await.unwrap();

    let key = Key {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: generated_key.public_key,
        name: "".to_string(),
        key_reference: generated_key.key_reference,
        storage_type: "".to_string(),
        key_type: "".to_string(),
        organisation: None,
    };

    provider.sign(&key, "message".as_bytes()).await.unwrap();
}
