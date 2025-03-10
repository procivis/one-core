//! Internal encrypted database implementation.

use std::sync::Arc;

use cocoon::MiniCocoon;
use one_crypto::{utilities, SignerError};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use serde::{Deserialize, Deserializer};
use shared_types::KeyId;

use crate::model::key::Key;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{
    Features, KeySecurity, KeyStorageCapabilities, StorageGeneratedKey,
};
use crate::provider::key_storage::KeyStorage;

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

pub fn deserialize_encryption_key<'de, D>(deserializer: D) -> Result<SecretSlice<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    const ERROR_MSG: &str = "Invalid encryption key: needs to be hex encoded 32 byte value";
    let s = SecretString::deserialize(deserializer)?;
    let secret = s.expose_secret();
    if secret.len() != 64 {
        return Err(serde::de::Error::custom(ERROR_MSG));
    }
    Ok(SecretSlice::from(
        hex::decode(secret).map_err(|_| serde::de::Error::custom(ERROR_MSG))?,
    ))
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
                "ES256".to_string(),
                "EDDSA".to_string(),
                "DILITHIUM".to_string(),
                "BBS_PLUS".to_string(),
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
            key_reference: encrypt_key(&key_pair.private, &self.encryption_key)?,
        })
    }

    fn key_handle(&self, key: &Key) -> Result<KeyHandle, SignerError> {
        let algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_name(&key.key_type)
            .ok_or(SignerError::MissingAlgorithm(key.key_type.clone()))?;

        let private_key = decrypt_key(&key.key_reference, &self.encryption_key)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;

        algorithm
            .reconstruct_key(&key.public_key, Some(private_key), None)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)
    }
}

fn decrypt_key(
    data: &[u8],
    encryption_key: &SecretSlice<u8>,
) -> Result<SecretSlice<u8>, KeyStorageError> {
    // seed is not used for decryption, so passing dummy value
    let cocoon = MiniCocoon::from_key(encryption_key.expose_secret(), &[0u8; 32]);
    cocoon
        .unwrap(data)
        .map(SecretSlice::from)
        .map_err(|_| KeyStorageError::PasswordDecryptionFailure)
}

fn encrypt_key(
    buffer: &SecretSlice<u8>,
    encryption_key: &SecretSlice<u8>,
) -> Result<Vec<u8>, KeyStorageError> {
    let mut cocoon = MiniCocoon::from_key(
        encryption_key.expose_secret(),
        &utilities::generate_random_seed_32(),
    );
    cocoon
        .wrap(buffer.expose_secret())
        .map_err(|_| KeyStorageError::Failed("Encryption failure".to_string()))
}
