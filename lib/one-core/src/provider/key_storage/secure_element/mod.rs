use serde::Deserialize;
use shared_types::KeyId;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::{
    crypto::signer::error::SignerError,
    model::key::Key,
    provider::key_storage::{GeneratedKey, KeyStorage, KeyStorageCapabilities},
    service::error::{ServiceError, ValidationError},
};

use super::KeySecurity;

#[cfg_attr(test, mockall::automock)]
pub trait NativeKeyStorage: Send + Sync {
    fn generate_key(&self, key_alias: String) -> Result<GeneratedKey, ServiceError>;
    fn sign(&self, key_reference: &[u8], message: &[u8]) -> Result<Vec<u8>, SignerError>;
}

pub struct SecureElementKeyProvider {
    native_storage: Arc<dyn NativeKeyStorage>,
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    alias_prefix: String,
}

#[async_trait::async_trait]
impl KeyStorage for SecureElementKeyProvider {
    async fn generate(&self, key_id: &KeyId, key_type: &str) -> Result<GeneratedKey, ServiceError> {
        if key_type != "ES256" {
            return Err(ValidationError::UnsupportedKeyType {
                key_type: key_type.to_owned(),
            }
            .into());
        }

        let key_alias = format!("{}.{}", self.params.alias_prefix, key_id);
        self.native_storage.generate_key(key_alias)
    }

    async fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.native_storage.sign(&key.key_reference, message)
    }

    fn secret_key_as_jwk(&self, _key: &Key) -> Result<Zeroizing<String>, ServiceError> {
        unimplemented!()
    }

    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities {
            algorithms: vec!["ES256".to_string()],
            security: vec![KeySecurity::Hardware],
            features: vec![],
        }
    }
}

impl SecureElementKeyProvider {
    pub fn new(native_storage: Arc<dyn NativeKeyStorage>, params: Params) -> Self {
        SecureElementKeyProvider {
            native_storage,
            params,
        }
    }
}

#[cfg(test)]
mod test;
