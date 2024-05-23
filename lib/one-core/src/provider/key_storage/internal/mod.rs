use std::sync::Arc;

use cocoon::MiniCocoon;
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rcgen::SignatureAlgorithm;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use shared_types::KeyId;
use zeroize::Zeroizing;

use crate::crypto::signer::error::SignerError;
use crate::crypto::signer::Signer;
use crate::model::key::Key;
use crate::service::error::{KeyStorageError, ValidationError};
use crate::{
    provider::{
        key_algorithm::provider::KeyAlgorithmProvider,
        key_storage::{GeneratedKey, KeyStorage, KeyStorageCapabilities},
    },
    service::error::ServiceError,
};

use super::KeySecurity;

#[cfg(test)]
mod test;

pub struct InternalKeyProvider {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    encryption_key: Option<[u8; 32]>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    encryption: Option<String>,
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

    fn secret_key_as_jwk(&self, key: &Key) -> Result<Zeroizing<String>, ServiceError> {
        let private_key = decrypt_if_password_is_provided(&key.key_reference, &self.encryption_key)
            .map(Zeroizing::new)
            .map_err(|err| {
                ServiceError::KeyStorageError(anyhow::anyhow!("Decryption failed: {err}"))
            })?;

        let key_type = &key.key_type;
        let provider = self
            .key_algorithm_provider
            .get_key_algorithm(key_type)
            .ok_or_else(|| ValidationError::InvalidKeyAlgorithm(key_type.to_owned()))?;

        provider
            .private_key_as_jwk(private_key)
            .map_err(|err| ServiceError::KeyStorageError(err.into()))
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
            features: vec!["EXPORTABLE".to_string()],
        }
    }
}

struct InternalRemoteKeyPair {
    pub crypto: Arc<dyn Signer>,
    pub encryption_key: Zeroizing<Option<[u8; 32]>>,
    pub public_key: Vec<u8>,
    pub private_key: Zeroizing<Vec<u8>>,
    pub key_type: String,
}

impl rcgen::RemoteKeyPair for InternalRemoteKeyPair {
    fn public_key(&self) -> &[u8] {
        self.public_key.as_slice()
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let private_key = Zeroizing::new(
            decrypt_if_password_is_provided(&self.private_key, &self.encryption_key)
                .map_err(|_| rcgen::Error::RemoteKeyError)?,
        );

        self.crypto
            .sign(msg, &self.public_key, &private_key)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        if self.key_type == "ES256" {
            &rcgen::PKCS_ECDSA_P256_SHA256
        } else {
            &rcgen::PKCS_ED25519
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
pub fn convert_passphrase_to_encryption_key(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase).into()
}
