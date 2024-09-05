use std::sync::Arc;

use mockall::predicate::eq;
use one_providers::common_models::key::OpenKey;
use one_providers::key_storage::error::KeyStorageError;
use one_providers::key_storage::model::StorageGeneratedKey;
use one_providers::key_storage::KeyStorage;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{MockNativeKeyStorage, Params, SecureElementKeyProvider};

fn get_params() -> Params {
    Params {
        alias_prefix: "prefix".to_string(),
    }
}

#[tokio::test]
async fn test_generate_success() {
    let mut native_storage = MockNativeKeyStorage::default();

    let key_id = Uuid::new_v4();
    native_storage
        .expect_generate_key()
        .once()
        .with(eq(format!("prefix.{key_id}")))
        .return_once(|_| {
            Ok(StorageGeneratedKey {
                public_key: b"public_key".into(),
                key_reference: b"key_reference".into(),
            })
        });

    let provider = SecureElementKeyProvider::new(Arc::new(native_storage), get_params());

    let result = provider
        .generate(Some(key_id.into()), "ES256")
        .await
        .unwrap();
    assert_eq!(result.public_key, b"public_key");
    assert_eq!(result.key_reference, b"key_reference");
}

#[tokio::test]
async fn test_generate_invalid_key_type() {
    let provider =
        SecureElementKeyProvider::new(Arc::new(MockNativeKeyStorage::default()), get_params());

    let result = provider
        .generate(Some(Uuid::new_v4().into()), "invalid")
        .await;
    assert!(matches!(
        result,
        Err(KeyStorageError::UnsupportedKeyType { .. })
    ));
}

#[tokio::test]
async fn test_sign_success() {
    let mut native_storage = MockNativeKeyStorage::default();
    native_storage
        .expect_sign()
        .once()
        .with(eq(b"key_reference".to_vec()), eq(b"message".to_vec()))
        .return_once(|_, _| Ok(b"signature".into()));

    let provider = SecureElementKeyProvider::new(Arc::new(native_storage), get_params());

    let result = provider
        .sign(
            &OpenKey {
                id: Uuid::new_v4().into(),
                key_reference: b"key_reference".to_vec(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: b"public_key".to_vec(),
                name: "".to_string(),
                storage_type: "SECURE_ELEMENT".to_string(),
                key_type: "ES256".to_string(),
                organisation: None,
            },
            "message".as_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(result, b"signature");
}
