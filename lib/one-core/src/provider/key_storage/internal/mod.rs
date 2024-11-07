//! Internal encrypted database implementation.

use std::sync::Arc;

use cocoon::MiniCocoon;
use one_crypto::{utilities, SignerError};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use shared_types::KeyId;
use zeroize::Zeroizing;

use crate::model::key::Key;
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
    encryption_key: Option<[u8; 32]>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub encryption: Option<String>,
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
    async fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        let signer = self
            .key_algorithm_provider
            .get_signer(&key.key_type)
            .map_err(|e| SignerError::MissingAlgorithm(e.to_string()))?;

        let private_key = decrypt_if_password_is_provided(&key.key_reference, &self.encryption_key)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;

        signer.sign(message, &key.public_key, &private_key)
    }

    async fn generate(
        &self,
        _key_id: Option<KeyId>,
        key_type: &str,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        let key_pair = self
            .key_algorithm_provider
            .get_key_algorithm(key_type)
            .ok_or(KeyStorageError::InvalidKeyAlgorithm(key_type.to_owned()))?
            .generate_key_pair();

        Ok(StorageGeneratedKey {
            public_key: key_pair.public,
            key_reference: encrypt_if_password_is_provided(
                &key_pair.private,
                &self.encryption_key,
            )?,
        })
    }

    fn secret_key_as_jwk(&self, key: &Key) -> Result<Zeroizing<String>, KeyStorageError> {
        let private_key = decrypt_if_password_is_provided(&key.key_reference, &self.encryption_key)
            .map(Zeroizing::new)
            .map_err(|err| {
                KeyStorageError::Failed(anyhow::anyhow!("Decryption failed: {err}").to_string())
            })?;

        let key_type = &key.key_type;
        let provider = self
            .key_algorithm_provider
            .get_key_algorithm(key_type)
            .ok_or_else(|| KeyStorageError::NotSupported(key_type.to_owned()))?;

        provider
            .private_key_as_jwk(private_key)
            .map_err(|err| err.into())
    }

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
}

pub fn decrypt_if_password_is_provided(
    data: &[u8],
    encryption_key: &Option<[u8; 32]>,
) -> Result<Vec<u8>, KeyStorageError> {
    match encryption_key {
        None => Ok(data.to_vec()),
        Some(encryption_key) => {
            // seed is not used for decryption, so passing dummy value
            let cocoon = MiniCocoon::from_key(encryption_key, &[0u8; 32]);
            cocoon
                .unwrap(data)
                .map_err(|_| KeyStorageError::PasswordDecryptionFailure)
        }
    }
}

fn encrypt_if_password_is_provided(
    buffer: &[u8],
    encryption_key: &Option<[u8; 32]>,
) -> Result<Vec<u8>, KeyStorageError> {
    match encryption_key {
        None => Ok(buffer.to_vec()),
        Some(encryption_key) => {
            let mut cocoon =
                MiniCocoon::from_key(encryption_key, &utilities::generate_random_seed_32());
            cocoon
                .wrap(buffer)
                .map_err(|_| KeyStorageError::Failed("Encryption failure".to_string()))
        }
    }
}

/// Simplified KDF
/// * TODO: use pbkdf2 or similar algorithm to prevent dictionary brute-force password attack
pub fn convert_passphrase_to_encryption_key(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase).into()
}
