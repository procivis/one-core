use cocoon::MiniCocoon;
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::crypto::signer::error::SignerError;
use crate::model::key::Key;
use crate::model::key::KeyId;
use crate::service::error::ValidationError;
use crate::{
    provider::{
        key_algorithm::provider::KeyAlgorithmProvider,
        key_storage::{GeneratedKey, KeyStorage, KeyStorageCapabilities},
    },
    service::error::ServiceError,
};

pub struct InternalKeyProvider {
    capabilities: KeyStorageCapabilities,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
    encryption_key: Option<[u8; 32]>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    encryption: Option<String>,
}

impl InternalKeyProvider {
    pub fn new(
        capabilities: KeyStorageCapabilities,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
        params: Params,
    ) -> Self {
        Self {
            capabilities,
            key_algorithm_provider,
            encryption_key: params
                .encryption
                .map(|passphrase| convert_passphrase_to_encryption_key(&passphrase)),
        }
    }
}

#[async_trait::async_trait]
impl KeyStorage for InternalKeyProvider {
    async fn sign(&self, key: &Key, message: &str) -> Result<Vec<u8>, SignerError> {
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
        _key_id: &KeyId,
        key_type: &str,
    ) -> Result<GeneratedKey, ServiceError> {
        let key_pair = self
            .key_algorithm_provider
            .get_key_algorithm(key_type)
            .ok_or(ValidationError::InvalidKeyAlgorithm(key_type.to_owned()))?
            .generate_key_pair();

        Ok(GeneratedKey {
            public_key: key_pair.public,
            key_reference: encrypt_if_password_is_provided(
                &key_pair.private,
                &self.encryption_key,
            )?,
        })
    }

    fn get_capabilities(&self) -> KeyStorageCapabilities {
        self.capabilities.to_owned()
    }
}

fn decrypt_if_password_is_provided(
    data: &[u8],
    encryption_key: &Option<[u8; 32]>,
) -> Result<Vec<u8>, ServiceError> {
    match encryption_key {
        None => Ok(data.to_vec()),
        Some(encryption_key) => {
            // seed is not used for decryption, so passing dummy value
            let cocoon = MiniCocoon::from_key(encryption_key, &[0u8; 32]);
            cocoon
                .unwrap(data)
                .map_err(|_| ServiceError::Other("Decryption failure".to_string()))
        }
    }
}

fn encrypt_if_password_is_provided(
    buffer: &[u8],
    encryption_key: &Option<[u8; 32]>,
) -> Result<Vec<u8>, ServiceError> {
    match encryption_key {
        None => Ok(buffer.to_vec()),
        Some(encryption_key) => {
            let mut cocoon = MiniCocoon::from_key(encryption_key, &generate_random_seed());
            cocoon
                .wrap(buffer)
                .map_err(|_| ServiceError::Other("Encryption failure".to_string()))
        }
    }
}

fn generate_random_seed() -> [u8; 32] {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    seed
}

/// Simplified KDF
/// * TODO: use pbkdf2 or similar algorithm to prevent dictionary brute-force password attack
fn convert_passphrase_to_encryption_key(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase).into()
}

#[cfg(test)]
mod test;
