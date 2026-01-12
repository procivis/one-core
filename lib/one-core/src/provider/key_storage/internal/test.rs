use std::sync::Arc;

use mockall::predicate;
use mockall::predicate::{always, eq};
use secrecy::{ExposeSecret, SecretSlice};
use similar_asserts::assert_eq;
use standardized_types::jwk::{PrivateJwk, PrivateJwkEc};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{InternalKeyProvider, decrypt_data};
use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePrivateKeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::model::GeneratedKey;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::internal::Params;

#[tokio::test]
async fn test_internal_generate_with_encryption() {
    let mut mock_key_algorithm = MockKeyAlgorithm::default();
    mock_key_algorithm.expect_generate_key().return_once(|| {
        Ok(GeneratedKey {
            key: KeyHandle::SignatureOnly(SignatureKeyHandle::WithPrivateKey {
                private: Arc::new(MockSignaturePrivateKeyHandle::default()),
                public: Arc::new(MockSignaturePublicKeyHandle::default()),
            }),
            public: vec![1],
            private: SecretSlice::from(vec![1, 2, 3]),
        })
    });

    let arc = Arc::new(mock_key_algorithm);

    let mut mock_key_algorithm_provider = MockKeyAlgorithmProvider::default();
    mock_key_algorithm_provider
        .expect_key_algorithm_from_type()
        .times(1)
        .returning(move |_| Some(arc.clone()));

    let provider = InternalKeyProvider::new(
        Arc::new(mock_key_algorithm_provider),
        Params {
            encryption: SecretSlice::from(vec![0; 32]),
        },
    );

    let result = provider
        .generate(Uuid::new_v4().into(), KeyAlgorithmType::Eddsa)
        .await
        .unwrap();
    assert_eq!(result.key_reference.as_ref().unwrap().len(), 39);
    let decrypted = decrypt_data(
        result.key_reference.as_ref().unwrap(),
        &SecretSlice::from(vec![0; 32]),
    )
    .unwrap();
    assert_eq!(decrypted.expose_secret(), vec![1, 2, 3]);
}

#[tokio::test]
async fn test_internal_sign_with_encryption() {
    let expected_signed_response = vec![1u8];

    let mut mock_key_algorithm = MockKeyAlgorithm::default();
    let signed = expected_signed_response.clone();
    mock_key_algorithm
        .expect_generate_key()
        .return_once(move || {
            Ok(GeneratedKey {
                key: KeyHandle::SignatureOnly(SignatureKeyHandle::WithPrivateKey {
                    private: Arc::new(MockSignaturePrivateKeyHandle::default()),
                    public: Arc::new(MockSignaturePublicKeyHandle::default()),
                }),
                public: vec![1],
                private: SecretSlice::from(vec![1, 2, 3]),
            })
        });
    mock_key_algorithm
        .expect_reconstruct_key()
        .with(
            eq(vec![1]),
            predicate::function(|val: &Option<SecretSlice<u8>>| {
                val.as_ref().unwrap().expose_secret() == vec![1, 2, 3]
            }),
            always(),
        )
        .return_once(|_, _, _| {
            let mut private_key_handle = MockSignaturePrivateKeyHandle::default();
            private_key_handle
                .expect_sign()
                .return_once(move |_| Ok(signed));

            Ok(KeyHandle::SignatureOnly(
                SignatureKeyHandle::WithPrivateKey {
                    private: Arc::new(private_key_handle),
                    public: Arc::new(MockSignaturePublicKeyHandle::default()),
                },
            ))
        });

    let arc_key_algorithm = Arc::new(mock_key_algorithm);

    let mut mock_key_algorithm_provider = MockKeyAlgorithmProvider::default();
    let arc_key_algorithm_clone = arc_key_algorithm.clone();
    mock_key_algorithm_provider
        .expect_key_algorithm_from_type()
        .once()
        .returning(move |_| Some(arc_key_algorithm_clone.clone()));

    mock_key_algorithm_provider
        .expect_key_algorithm_from_type()
        .once()
        .returning(move |_| Some(arc_key_algorithm.clone()));

    let provider = InternalKeyProvider::new(
        Arc::new(mock_key_algorithm_provider),
        Params {
            encryption: SecretSlice::from(vec![0; 32]),
        },
    );

    let generated_key = provider
        .generate(Uuid::new_v4().into(), KeyAlgorithmType::Eddsa)
        .await
        .unwrap();

    let key = Key {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: generated_key.public_key,
        name: "".to_string(),
        key_reference: generated_key.key_reference,
        storage_type: "".to_string(),
        key_type: "EDDSA".to_string(),
        organisation: None,
    };

    let key_handle = provider.key_handle(&key).unwrap();

    key_handle.sign("message".as_bytes()).await.unwrap();
}

#[tokio::test]
async fn test_internal_import() {
    let mut mock_key_algorithm = MockKeyAlgorithm::default();
    mock_key_algorithm
        .expect_parse_private_jwk()
        .return_once(|_| {
            Ok(GeneratedKey {
                key: KeyHandle::SignatureOnly(SignatureKeyHandle::WithPrivateKey {
                    private: Arc::new(MockSignaturePrivateKeyHandle::default()),
                    public: Arc::new(MockSignaturePublicKeyHandle::default()),
                }),
                public: vec![1],
                private: SecretSlice::from(vec![1, 2, 3]),
            })
        });

    let arc = Arc::new(mock_key_algorithm);

    let mut mock_key_algorithm_provider = MockKeyAlgorithmProvider::default();
    mock_key_algorithm_provider
        .expect_key_algorithm_from_type()
        .times(1)
        .returning(move |_| Some(arc.clone()));

    let provider = InternalKeyProvider::new(
        Arc::new(mock_key_algorithm_provider),
        Params {
            encryption: SecretSlice::from(vec![0; 32]),
        },
    );

    provider
        .import(
            Uuid::new_v4().into(),
            KeyAlgorithmType::Ecdsa,
            PrivateJwk::Ec(PrivateJwkEc {
                r#use: None,
                kid: Some("13ae667d-392b-4c00-8896-079909fe85d7".to_string()),
                crv: "P-256".to_string(),
                x: "r1U6-8dqlyj-_CwYft6kxx9MCfInQYCoUwKiP579c3w".to_string(),
                y: Some("u_EMmvFmfsUjDmDY2kBhZPK0tyycAylkoY-PLAUD1WU".to_string()),
                d: "_M90X3GfBZoFDBZHZsMQszc2a92dCorIJBlytnmkKEM".into(),
            }),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_internal_import_jwk_invalid_key_type() {
    let mock_key_algorithm_provider = MockKeyAlgorithmProvider::default();

    let provider = InternalKeyProvider::new(
        Arc::new(mock_key_algorithm_provider),
        Params {
            encryption: SecretSlice::from(vec![0; 32]),
        },
    );

    let result = provider
        .import(
            Uuid::new_v4().into(),
            KeyAlgorithmType::Ecdsa,
            PrivateJwk::Okp(PrivateJwkEc {
                r#use: None,
                kid: Some("13ae667d-392b-4c00-8896-079909fe85d7".to_string()),
                crv: "P-256".to_string(),
                x: "r1U6-8dqlyj-_CwYft6kxx9MCfInQYCoUwKiP579c3w".to_string(),
                y: Some("u_EMmvFmfsUjDmDY2kBhZPK0tyycAylkoY-PLAUD1WU".to_string()),
                d: "_M90X3GfBZoFDBZHZsMQszc2a92dCorIJBlytnmkKEM".into(),
            }),
        )
        .await;
    assert!(matches!(
        result,
        Err(KeyStorageError::InvalidKeyAlgorithm(_))
    ));
}
