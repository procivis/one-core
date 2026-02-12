//! Internal encrypted database implementation.

use std::sync::Arc;

use one_crypto::SignerError;
use one_crypto::encryption::{decrypt_data, encrypt_data};
use secrecy::SecretSlice;
use serde::Deserialize;
use shared_types::KeyId;
use standardized_types::jwk::PrivateJwk;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::mapper::params::deserialize_encryption_key;
use crate::model::key::{Key, PrivateJwkExt};
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{Features, KeyStorageCapabilities, StorageGeneratedKey};

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
                KeyAlgorithmType::MlDsa,
                KeyAlgorithmType::BbsPlus,
            ],
            features: vec![Features::Exportable, Features::Importable],
        }
    }

    async fn generate(
        &self,
        _key_id: KeyId,
        key_type: KeyAlgorithmType,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        let key_pair = self
            .key_algorithm_provider
            .key_algorithm_from_type(key_type)
            .ok_or(KeyStorageError::InvalidKeyAlgorithm(key_type.to_string()))?
            .generate_key()
            .error_while("generating key")?;

        Ok(StorageGeneratedKey {
            public_key: key_pair.public,
            key_reference: Some(
                encrypt_data(&key_pair.private, &self.encryption_key)
                    .map_err(KeyStorageError::Encryption)?,
            ),
        })
    }

    async fn import(
        &self,
        _key_id: KeyId,
        key_type: KeyAlgorithmType,
        jwk: PrivateJwk,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        if !self
            .get_capabilities()
            .features
            .contains(&Features::Importable)
        {
            return Err(KeyStorageError::UnsupportedFeature {
                feature: Features::Importable,
            });
        }
        if jwk.supported_key_type() != key_type {
            return Err(KeyStorageError::InvalidKeyAlgorithm(key_type.to_string()));
        };

        let key_pair = self
            .key_algorithm_provider
            .key_algorithm_from_type(key_type)
            .ok_or(KeyStorageError::InvalidKeyAlgorithm(key_type.to_string()))?
            .parse_private_jwk(jwk)
            .error_while("parsing private JWK")?;

        Ok(StorageGeneratedKey {
            public_key: key_pair.public,
            key_reference: Some(
                encrypt_data(&key_pair.private, &self.encryption_key)
                    .map_err(KeyStorageError::Encryption)?,
            ),
        })
    }

    fn key_handle(&self, key: &Key) -> Result<KeyHandle, SignerError> {
        let algorithm = key
            .key_algorithm_type()
            .and_then(|alg| self.key_algorithm_provider.key_algorithm_from_type(alg))
            .ok_or(SignerError::MissingAlgorithm(key.key_type.clone()))?;

        let key_reference = key
            .key_reference
            .as_ref()
            .ok_or(SignerError::MissingKeyReference)?;
        let private_key = decrypt_data(key_reference, &self.encryption_key)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;

        algorithm
            .reconstruct_key(&key.public_key, Some(private_key), None)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)
    }

    async fn generate_attestation_key(
        &self,
        _key_id: KeyId,
        _nonce: Option<String>,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        return Err(KeyStorageError::UnsupportedFeature {
            feature: Features::Attestation,
        });
    }

    async fn generate_attestation(
        &self,
        _key: &Key,
        _nonce: Option<String>,
    ) -> Result<Vec<String>, KeyStorageError> {
        return Err(KeyStorageError::UnsupportedFeature {
            feature: Features::Attestation,
        });
    }

    async fn sign_with_attestation_key(
        &self,
        _key: &Key,
        _data: &[u8],
    ) -> Result<Vec<u8>, KeyStorageError> {
        return Err(KeyStorageError::UnsupportedFeature {
            feature: Features::Attestation,
        });
    }
}
