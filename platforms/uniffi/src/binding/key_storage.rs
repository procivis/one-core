use std::sync::Arc;

use one_core::provider::key_storage::error::KeyStorageError;
use one_core::provider::key_storage::model::StorageGeneratedKey;
use one_crypto::SignerError;
use one_dto_mapper::Into;

use crate::error::NativeKeyStorageError;

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait NativeKeyStorage: Send + Sync {
    async fn generate_key(
        &self,
        key_alias: String,
    ) -> Result<GeneratedKeyBindingDTO, NativeKeyStorageError>;
    async fn sign(
        &self,
        key_reference: Vec<u8>,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, NativeKeyStorageError>;
    async fn generate_attestation_key(
        &self,
        key_alias: String,
        nonce: Option<String>,
    ) -> Result<GeneratedKeyBindingDTO, NativeKeyStorageError>;
    async fn generate_attestation(
        &self,
        key_reference: Vec<u8>,
        nonce: Option<String>,
    ) -> Result<Vec<String>, NativeKeyStorageError>;
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(StorageGeneratedKey)]
pub struct GeneratedKeyBindingDTO {
    pub key_reference: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Adapter between `NativeKeyStorage` interfaces (one_core lib and uniffi bindings)
pub struct NativeKeyStorageWrapper(pub Arc<dyn NativeKeyStorage>);

#[async_trait::async_trait]
impl one_core::provider::key_storage::secure_element::NativeKeyStorage for NativeKeyStorageWrapper {
    async fn generate_key(
        &self,
        key_alias: String,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        Ok(self.0.generate_key(key_alias).await?.into())
    }

    async fn sign(&self, key_reference: &[u8], message: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.0
            .sign(key_reference.into(), message.to_owned())
            .await
            .map_err(SignerError::from)
    }

    async fn generate_attestation_key(
        &self,
        key_alias: String,
        nonce: Option<String>,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        Ok(self
            .0
            .generate_attestation_key(key_alias, nonce)
            .await?
            .into())
    }

    async fn generate_attestation(
        &self,
        key_reference: &[u8],
        nonce: Option<String>,
    ) -> Result<Vec<String>, KeyStorageError> {
        self.0
            .generate_attestation(key_reference.into(), nonce)
            .await
            .map_err(KeyStorageError::from)
    }
}
