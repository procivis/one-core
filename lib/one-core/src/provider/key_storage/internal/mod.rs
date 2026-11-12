//! Internal encrypted database implementation.

use std::sync::Arc;

use one_crypto::encryption::{decrypt_data, encrypt_data};
use proc_macros::Provider;
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
use crate::provider::provider_directory::InitializationError;

#[cfg(test)]
mod test;

#[derive(Provider)]
pub struct InternalKeyProvider {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    encryption_key: SecretSlice<u8>,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde(deserialize_with = "deserialize_encryption_key")]
    pub encryption: SecretSlice<u8>,
}

impl InternalKeyProvider {
    pub fn new(
        name: &str,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        params: serde_json::Value,
    ) -> Result<Self, InitializationError> {
        let params: Params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: name.to_string(),
                source: err,
            })?;
        Ok(Self {
            key_algorithm_provider,
            encryption_key: params.encryption,
            name: name.to_string(),
        })
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
            features: vec![
                Features::Exportable,
                Features::Importable,
                Features::KeyAgreement,
            ],
        }
    }
    fn config_name(&self) -> String {
        self.name.clone()
    }

    async fn generate(
        &self,
        _key_id: KeyId,
        key_type: KeyAlgorithmType,
        _params: serde_json::Value,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        let key_pair = self
            .key_algorithm_provider
            .key_algorithm_from_type(key_type)?
            .generate_key()
            .error_while("generating key")?;

        Ok(StorageGeneratedKey {
            public_key: key_pair.public,
            key_reference: Some(encrypt_data(&key_pair.private, &self.encryption_key)?),
        })
    }

    async fn import(
        &self,
        _key_id: KeyId,
        key_type: KeyAlgorithmType,
        jwk: PrivateJwk,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        if jwk.supported_key_type() != key_type {
            return Err(KeyStorageError::InvalidKeyAlgorithm(key_type.to_string()));
        };

        let key_pair = self
            .key_algorithm_provider
            .key_algorithm_from_type(key_type)?
            .parse_private_jwk(jwk)
            .error_while("parsing private JWK")?;

        Ok(StorageGeneratedKey {
            public_key: key_pair.public,
            key_reference: Some(encrypt_data(&key_pair.private, &self.encryption_key)?),
        })
    }

    fn key_handle(&self, key: &Key) -> Result<KeyHandle, KeyStorageError> {
        let algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_key(key)
            .error_while("getting key algorithm")?;

        let key_reference = key
            .key_reference
            .as_ref()
            .ok_or(KeyStorageError::MissingKeyReference)?;
        let private_key = decrypt_data(key_reference, &self.encryption_key)?;

        Ok(algorithm
            .reconstruct_key(&key.public_key, Some(private_key), None)
            .error_while("reconstructing key")?)
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
