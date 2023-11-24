use one_core::{
    crypto::signer::error::SignerError, provider::key_storage::GeneratedKey,
    service::error::ServiceError,
};

/// Adapter between `NativeKeyStorage` interfaces (one_core lib and uniffi bindings)
pub struct NativeKeyStorageWrapper(pub Box<dyn crate::dto::NativeKeyStorage>);

impl one_core::provider::key_storage::secure_element::NativeKeyStorage for NativeKeyStorageWrapper {
    fn generate_key(&self, key_alias: String) -> Result<GeneratedKey, ServiceError> {
        Ok(self
            .0
            .generate_key(key_alias)
            .map_err(|e| ServiceError::Other(e.to_string()))?
            .into())
    }

    fn sign(&self, key_reference: &[u8], message: Vec<u8>) -> Result<Vec<u8>, SignerError> {
        self.0
            .sign(key_reference.into(), message)
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))
    }
}