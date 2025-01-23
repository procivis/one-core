use one_core::provider::key_storage::error::KeyStorageError;
use one_core::provider::key_storage::model::StorageGeneratedKey;
use one_crypto::SignerError;
use one_dto_mapper::Into;

use crate::error::NativeKeyStorageError;

#[uniffi::export(callback_interface)]
pub trait NativeKeyStorage: Send + Sync {
    fn generate_key(
        &self,
        key_alias: String,
    ) -> Result<GeneratedKeyBindingDTO, NativeKeyStorageError>;
    fn sign(
        &self,
        key_reference: Vec<u8>,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, NativeKeyStorageError>;
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(StorageGeneratedKey)]
pub struct GeneratedKeyBindingDTO {
    pub key_reference: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Adapter between `NativeKeyStorage` interfaces (one_core lib and uniffi bindings)
pub struct NativeKeyStorageWrapper(pub Box<dyn NativeKeyStorage>);

impl one_core::provider::key_storage::secure_element::NativeKeyStorage for NativeKeyStorageWrapper {
    fn generate_key(&self, key_alias: String) -> Result<StorageGeneratedKey, KeyStorageError> {
        Ok(self.0.generate_key(key_alias)?.into())
    }

    fn sign(&self, key_reference: &[u8], message: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.0
            .sign(key_reference.into(), message.to_owned())
            .map_err(SignerError::from)
    }
}
