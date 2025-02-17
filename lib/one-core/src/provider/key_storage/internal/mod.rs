//! Internal encrypted database implementation.

use std::sync::Arc;

use cocoon::MiniCocoon;
use one_crypto::{utilities, SignerError};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use serde::Deserialize;
use sha2::{Digest, Sha256};
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
    encryption_key: Option<SecretSlice<u8>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub encryption: Option<SecretString>,
}

impl InternalKeyProvider {
    pub fn new(key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>, params: Params) -> Self {
        Self {
            key_algorithm_provider,
            encryption_key: params
                .encryption
                .map(|passphrase| convert_passphrase_to_encryption_key(&passphrase)),
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
            key_reference: encrypt_if_password_is_provided(
                &key_pair.private,
                &self.encryption_key,
            )?,
        })
    }

    fn key_handle(&self, key: &Key) -> Result<KeyHandle, SignerError> {
        let algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_name(&key.key_type)
            .ok_or(SignerError::MissingAlgorithm(key.key_type.clone()))?;

        let private_key = decrypt_if_password_is_provided(&key.key_reference, &self.encryption_key)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;

        algorithm
            .reconstruct_key(&key.public_key, Some(private_key), None)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)
    }
}

pub fn decrypt_if_password_is_provided(
    data: &[u8],
    encryption_key: &Option<SecretSlice<u8>>,
) -> Result<SecretSlice<u8>, KeyStorageError> {
    match encryption_key {
        None => Ok(SecretSlice::from(data.to_vec())),
        Some(encryption_key) => {
            // seed is not used for decryption, so passing dummy value
            let cocoon = MiniCocoon::from_key(encryption_key.expose_secret(), &[0u8; 32]);
            cocoon
                .unwrap(data)
                .map(SecretSlice::from)
                .map_err(|_| KeyStorageError::PasswordDecryptionFailure)
        }
    }
}

fn encrypt_if_password_is_provided(
    buffer: &SecretSlice<u8>,
    encryption_key: &Option<SecretSlice<u8>>,
) -> Result<Vec<u8>, KeyStorageError> {
    match encryption_key {
        None => Ok(buffer.expose_secret().to_vec()),
        Some(encryption_key) => {
            let mut cocoon = MiniCocoon::from_key(
                encryption_key.expose_secret(),
                &utilities::generate_random_seed_32(),
            );
            cocoon
                .wrap(buffer.expose_secret())
                .map_err(|_| KeyStorageError::Failed("Encryption failure".to_string()))
        }
    }
}

/// Simplified KDF
/// * TODO: use pbkdf2 or similar algorithm to prevent dictionary brute-force password attack
pub fn convert_passphrase_to_encryption_key(passphrase: &SecretString) -> SecretSlice<u8> {
    SecretSlice::from(Sha256::digest(passphrase.expose_secret()).to_vec())
}
