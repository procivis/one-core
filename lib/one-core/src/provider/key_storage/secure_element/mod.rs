use std::sync::Arc;

use coset::CoseKey;
use one_crypto::signer::ecdsa::ECDSASigner;
use one_crypto::{Signer, SignerError};
use proc_macros::Provider;
use serde::Deserialize;
use shared_types::{KeyId, KeyStorageId};
use standardized_types::jwk::{PrivateJwk, PublicJwk};

use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::model::key::Key;
use crate::provider::key_algorithm::ecdsa::{
    ecdsa_public_key_as_cose, ecdsa_public_key_as_jwk, ecdsa_public_key_as_multibase,
};
use crate::provider::key_algorithm::key::{
    KeyHandle, KeyHandleError, SignatureKeyHandle, SignaturePrivateKeyHandle,
    SignaturePublicKeyHandle,
};
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{Features, KeyStorageCapabilities, StorageGeneratedKey};
use crate::provider::provider_directory::InitializationError;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait NativeKeyStorage: Send + Sync {
    async fn generate_key(&self, key_alias: String)
    -> Result<StorageGeneratedKey, KeyStorageError>;
    async fn sign(&self, key_reference: &[u8], message: &[u8]) -> Result<Vec<u8>, SignerError>;
    async fn generate_attestation_key(
        &self,
        key_alias: String,
        nonce: Option<String>,
    ) -> Result<StorageGeneratedKey, KeyStorageError>;
    async fn generate_attestation(
        &self,
        key: &[u8],
        nonce: Option<String>,
    ) -> Result<Vec<String>, KeyStorageError>;
    async fn sign_with_attestation_key(
        &self,
        key: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, KeyStorageError>;
}

#[derive(Provider)]
pub struct SecureElementKeyProvider {
    native_storage: Arc<dyn NativeKeyStorage>,
    params: Params,
    name: KeyStorageId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    alias_prefix: String,
}

#[async_trait::async_trait]
impl KeyStorage for SecureElementKeyProvider {
    fn get_capabilities(&self) -> KeyStorageCapabilities {
        KeyStorageCapabilities {
            algorithms: vec![KeyAlgorithmType::Ecdsa],
            features: vec![Features::Attestation],
        }
    }
    fn config_name(&self) -> KeyStorageId {
        self.name.clone()
    }

    async fn generate(
        &self,
        key_id: KeyId,
        _key_type: KeyAlgorithmType,
        _params: serde_json::Value,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        let key_alias = format!("{}.{}", self.params.alias_prefix, key_id);
        self.native_storage.generate_key(key_alias).await
    }

    async fn import(
        &self,
        _key_id: KeyId,
        _key_algorithm: KeyAlgorithmType,
        _jwk: PrivateJwk,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        Err(KeyStorageError::UnsupportedFeature {
            feature: Features::Importable,
        })
    }

    fn key_handle(&self, key: &Key) -> Result<KeyHandle, KeyStorageError> {
        let handle = SecureElementKeyHandle {
            key: key.clone(),
            native_storage: self.native_storage.clone(),
        };

        Ok(KeyHandle::SignatureOnly(
            SignatureKeyHandle::WithPrivateKey {
                private: Arc::new(handle.clone()),
                public: Arc::new(handle),
            },
        ))
    }

    async fn generate_attestation_key(
        &self,
        key_id: KeyId,
        nonce: Option<String>,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        let key_alias = format!("{}.{}", self.params.alias_prefix, key_id);

        self.native_storage
            .generate_attestation_key(key_alias, nonce)
            .await
    }

    async fn generate_attestation(
        &self,
        key: &Key,
        nonce: Option<String>,
    ) -> Result<Vec<String>, KeyStorageError> {
        let key_reference = key
            .key_reference
            .as_ref()
            .ok_or(KeyStorageError::Failed(format!(
                "Missing key reference for key {}",
                key.id
            )))?;

        self.native_storage
            .generate_attestation(key_reference, nonce)
            .await
    }

    async fn sign_with_attestation_key(
        &self,
        key: &Key,
        message: &[u8],
    ) -> Result<Vec<u8>, KeyStorageError> {
        let key_reference = key
            .key_reference
            .as_ref()
            .ok_or(KeyStorageError::Failed(format!(
                "Missing key reference for key {}",
                key.id
            )))?;

        self.native_storage
            .sign_with_attestation_key(key_reference, message)
            .await
    }
}

impl SecureElementKeyProvider {
    pub fn new(
        name: &KeyStorageId,
        native_storage: Arc<dyn NativeKeyStorage>,
        params: serde_json::Value,
    ) -> Result<Self, InitializationError> {
        let params: Params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: name.to_string(),
                source: err,
            })?;
        Ok(SecureElementKeyProvider {
            native_storage,
            params,
            name: name.to_owned(),
        })
    }
}

#[derive(Clone)]
struct SecureElementKeyHandle {
    key: Key,
    native_storage: Arc<dyn NativeKeyStorage>,
}

impl SignaturePublicKeyHandle for SecureElementKeyHandle {
    fn as_jwk(&self) -> Result<PublicJwk, KeyHandleError> {
        ecdsa_public_key_as_jwk(&self.key.public_key, None)
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        ecdsa_public_key_as_multibase(&self.key.public_key)
    }

    fn as_raw(&self) -> Vec<u8> {
        self.key.public_key.clone()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), KeyHandleError> {
        Ok(ECDSASigner.verify(message, signature, &self.key.public_key)?)
    }

    fn as_cose(&self) -> Result<CoseKey, KeyHandleError> {
        ecdsa_public_key_as_cose(&self.key.public_key)
    }

    fn as_der(&self) -> Result<Vec<u8>, KeyHandleError> {
        Ok(ECDSASigner::public_key_to_der(&self.key.public_key)?)
    }
}

#[async_trait::async_trait]
impl SignaturePrivateKeyHandle for SecureElementKeyHandle {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyHandleError> {
        let key_reference = self
            .key
            .key_reference
            .as_ref()
            .ok_or(KeyStorageError::MissingKeyReference)
            .error_while("signing")?;
        Ok(self.native_storage.sign(key_reference, message).await?)
    }
}

#[cfg(test)]
mod test;
