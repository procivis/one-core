//! Internal encrypted database implementation.

use std::sync::Arc;

use one_crypto::SignerError;
use one_crypto::encryption::{decrypt_data, encrypt_data};
use secrecy::SecretSlice;
use serde::Deserialize;
use shared_types::KeyId;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{
    Features, KeySecurity, KeyStorageCapabilities, StorageGeneratedKey,
};
use crate::util::params::deserialize_encryption_key;

#[cfg(test)]
mod test;

pub struct InternalKeyProvider {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    encryption_key: SecretSlice<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde(deserialize_with = "deserialize_encryption_key")]
    pub encryption: SecretSlice<u8>,
}

impl InternalKeyProvider {
    pub fn new(key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>, params: Params) -> Self {
        Self {
            key_algorithm_provider,
            encryption_key: params.encryption,
        }
    }
}

#[async_trait::async_trait]
impl KeyStorage for InternalKeyProvider {
    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities {
            algorithms: vec![
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::Dilithium,
                KeyAlgorithmType::BbsPlus,
            ],
            security: vec![KeySecurity::Software],
            features: vec![Features::Exportable],
        }
    }

    async fn generate(
        &self,
        _key_id: KeyId,
        key_type: &str,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        let key_pair = self
            .key_algorithm_provider
            .key_algorithm_from_name(key_type)
            .ok_or(KeyStorageError::InvalidKeyAlgorithm(key_type.to_owned()))?
            .generate_key()
            .map_err(KeyStorageError::KeyAlgorithmError)?;

        Ok(StorageGeneratedKey {
            public_key: key_pair.public,
            key_reference: encrypt_data(&key_pair.private, &self.encryption_key)
                .map_err(KeyStorageError::Encryption)?,
        })
    }

    fn key_handle(&self, key: &Key) -> Result<KeyHandle, SignerError> {
        let algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_name(&key.key_type)
            .ok_or(SignerError::MissingAlgorithm(key.key_type.clone()))?;

        let private_key = decrypt_data(&key.key_reference, &self.encryption_key)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;

        algorithm
            .reconstruct_key(&key.public_key, Some(private_key), None)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)
    }
}
