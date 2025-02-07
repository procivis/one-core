use std::sync::Arc;

use mockall::predicate::eq;
use time::OffsetDateTime;
use uuid::Uuid;

use super::RemoteSecureElementKeyProvider;
use crate::model::key::Key;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::StorageGeneratedKey;
use crate::provider::key_storage::secure_element::MockNativeKeyStorage;
use crate::provider::key_storage::KeyStorage;

#[tokio::test]
async fn test_generate_success() {
    let mut native_storage = MockNativeKeyStorage::default();

    let key_id = Uuid::new_v4();
    native_storage
        .expect_generate_key()
        .once()
        .with(eq(key_id.to_string()))
        .return_once(|_| {
            Ok(StorageGeneratedKey {
                public_key: b"public_key".into(),
                key_reference: b"key_reference".into(),
            })
        });

    let provider = RemoteSecureElementKeyProvider::new(Arc::new(native_storage));

    let result = provider.generate(key_id.into(), "EDDSA").await.unwrap();
    assert_eq!(result.public_key, b"public_key");
    assert_eq!(result.key_reference, b"key_reference");
}

#[tokio::test]
async fn test_generate_invalid_key_type() {
    let provider = RemoteSecureElementKeyProvider::new(Arc::new(MockNativeKeyStorage::default()));

    let result = provider.generate(Uuid::new_v4().into(), "invalid").await;
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

    let provider = RemoteSecureElementKeyProvider::new(Arc::new(native_storage));

    let key_handle = provider
        .key_handle(&Key {
            id: Uuid::new_v4().into(),
            key_reference: b"key_reference".to_vec(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            public_key: b"public_key".to_vec(),
            name: "".to_string(),
            storage_type: "REMOTE_SECURE_ELEMENT".to_string(),
            key_type: "EDDSA".to_string(),
            organisation: None,
        })
        .unwrap();

    let result = key_handle.sign("message".as_bytes()).await.unwrap();
    assert_eq!(result, b"signature");
}
