use std::sync::Arc;

use mockall::predicate::eq;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{MockNativeKeyStorage, Params, SecureElementKeyProvider};
use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::{Key, PrivateKeyJwk, PrivateKeyJwkEllipticData};
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::StorageGeneratedKey;

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
        .generate(key_id.into(), KeyAlgorithmType::Ecdsa)
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
        .generate(Uuid::new_v4().into(), KeyAlgorithmType::Dilithium)
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

    let key_handle = provider
        .key_handle(&Key {
            id: Uuid::new_v4().into(),
            key_reference: b"key_reference".to_vec(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            public_key: b"public_key".to_vec(),
            name: "".to_string(),
            storage_type: "SECURE_ELEMENT".to_string(),
            key_type: "ECDSA".to_string(),
            organisation: None,
        })
        .unwrap();

    let result = key_handle.sign("message".as_bytes()).await.unwrap();
    assert_eq!(result, b"signature");
}

#[tokio::test]
async fn test_import_failure() {
    let native_storage = MockNativeKeyStorage::default();

    let key_id = Uuid::new_v4();

    let provider = SecureElementKeyProvider::new(Arc::new(native_storage), get_params());

    let result = provider
        .import(
            key_id.into(),
            KeyAlgorithmType::Eddsa,
            PrivateKeyJwk::Okp(PrivateKeyJwkEllipticData {
                r#use: None,
                kid: None,
                crv: "".to_string(),
                x: "".to_string(),
                y: None,
                d: Default::default(),
            }),
        )
        .await;
    assert!(matches!(
        result,
        Err(KeyStorageError::UnsupportedFeature { .. })
    ));
}
