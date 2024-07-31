use one_providers::{
    crypto::SignerError,
    key_storage::{error::KeyStorageError, model::StorageGeneratedKey},
};

/// Adapter between `NativeKeyStorage` interfaces (one_core lib and uniffi bindings)
pub struct NativeKeyStorageWrapper(pub Box<dyn crate::dto::NativeKeyStorage>);

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
