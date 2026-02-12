//! Key storage provider.

use std::collections::HashMap;
use std::sync::Arc;

use one_crypto::{CryptoProvider, SignerError};
use serde_json::json;

use super::KeyStorage;
use super::azure_vault::AzureVaultKeyProvider;
use super::error::KeyStorageProviderError;
use super::internal::InternalKeyProvider;
use super::pkcs11::PKCS11KeyProvider;
use super::remote_secure_element::RemoteSecureElementKeyProvider;
use super::secure_element::{NativeKeyStorage, SecureElementKeyProvider};
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, KeyAlgorithmType, KeyStorageType};
use crate::error::ContextWithErrorCode;
use crate::model::key::Key;
use crate::proto::http_client::HttpClient;
use crate::provider::credential_formatter::model::{AuthenticationFn, SignatureProvider};
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait KeyProvider: Send + Sync {
    fn get_key_storage(&self, key_provider_id: &str) -> Option<Arc<dyn KeyStorage>>;

    fn get_signature_provider(
        &self,
        key: &Key,
        jwk_key_id: Option<String>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Result<AuthenticationFn, KeyStorageProviderError> {
        let key_handle = self
            .get_key_storage(&key.storage_type)
            .ok_or(KeyStorageProviderError::InvalidKeyStorage(
                key.storage_type.clone(),
            ))?
            .key_handle(key)
            .error_while("getting key storage")?;

        Ok(Box::new(SignatureProviderImpl {
            key: key.to_owned(),
            key_handle,
            jwk_key_id,
            key_algorithm_provider,
        }))
    }

    fn get_attestation_signature_provider(
        &self,
        key: &Key,
        jwk_key_id: Option<String>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Result<AuthenticationFn, KeyStorageProviderError> {
        let key_storage = self.get_key_storage(&key.storage_type).ok_or(
            KeyStorageProviderError::InvalidKeyStorage(key.storage_type.clone()),
        )?;

        Ok(Box::new(AttestationSignatureProvider {
            key: key.to_owned(),
            key_storage,
            jwk_key_id,
            key_algorithm_provider,
        }))
    }
}

struct KeyProviderImpl {
    storages: HashMap<String, Arc<dyn KeyStorage>>,
}

impl KeyProvider for KeyProviderImpl {
    fn get_key_storage(&self, format: &str) -> Option<Arc<dyn KeyStorage>> {
        self.storages.get(format).cloned()
    }
}

pub(crate) struct SignatureProviderImpl {
    pub key: Key,
    pub key_handle: KeyHandle,
    pub jwk_key_id: Option<String>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

pub(crate) struct AttestationSignatureProvider {
    pub key: Key,
    pub key_storage: Arc<dyn KeyStorage>,
    pub jwk_key_id: Option<String>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

#[async_trait::async_trait]
impl SignatureProvider for SignatureProviderImpl {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.key_handle
            .sign(message)
            .await
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))
    }

    fn get_key_id(&self) -> Option<String> {
        self.jwk_key_id.to_owned()
    }

    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, String> {
        self.key
            .key_algorithm_type()
            .ok_or(self.key.key_type.to_owned())
    }

    fn jose_alg(&self) -> Option<String> {
        self.key
            .key_algorithm_type()
            .and_then(|alg| self.key_algorithm_provider.key_algorithm_from_type(alg))
            .and_then(|key_algorithm| key_algorithm.issuance_jose_alg_id())
    }

    fn get_public_key(&self) -> Vec<u8> {
        self.key.public_key.to_owned()
    }
}

#[async_trait::async_trait]
impl SignatureProvider for AttestationSignatureProvider {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.key_storage
            .sign_with_attestation_key(&self.key, message)
            .await
            .map_err(|e| SignerError::CouldNotSign(e.to_string()))
    }

    fn get_key_id(&self) -> Option<String> {
        self.jwk_key_id.to_owned()
    }

    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, String> {
        self.key
            .key_algorithm_type()
            .ok_or(self.key.key_type.to_owned())
    }

    fn jose_alg(&self) -> Option<String> {
        self.key
            .key_algorithm_type()
            .and_then(|alg| self.key_algorithm_provider.key_algorithm_from_type(alg))
            .and_then(|key_algorithm| key_algorithm.issuance_jose_alg_id())
    }

    fn get_public_key(&self) -> Vec<u8> {
        self.key.public_key.to_owned()
    }
}

pub(crate) fn key_provider_from_config(
    config: &mut CoreConfig,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    crypto: Arc<dyn CryptoProvider>,
    client: Arc<dyn HttpClient>,
    native_secure_element: Option<Arc<dyn NativeKeyStorage>>,
    remote_secure_element: Option<Arc<dyn NativeKeyStorage>>,
) -> Result<Arc<dyn KeyProvider>, ConfigValidationError> {
    let mut storages: HashMap<String, Arc<dyn KeyStorage>> = HashMap::new();

    for (name, field) in config.key_storage.iter() {
        let storage: Arc<dyn KeyStorage> =
            match field.r#type {
                KeyStorageType::Internal => {
                    let params = config.key_storage.get(name)?;
                    Arc::new(InternalKeyProvider::new(
                        key_algorithm_provider.clone(),
                        params,
                    ))
                }
                KeyStorageType::PKCS11 => Arc::new(PKCS11KeyProvider::new()),
                KeyStorageType::AzureVault => {
                    let params = config.key_storage.get(name)?;
                    Arc::new(AzureVaultKeyProvider::new(
                        params,
                        crypto.clone(),
                        client.clone(),
                    ))
                }
                KeyStorageType::SecureElement => {
                    let native_storage = native_secure_element.clone().ok_or(
                        ConfigValidationError::EntryNotFound("native key provider".to_string()),
                    )?;
                    let params = config.key_storage.get(name)?;
                    Arc::new(SecureElementKeyProvider::new(native_storage, params))
                }
                KeyStorageType::RemoteSecureElement => {
                    let native_storage = remote_secure_element.clone().ok_or(
                        ConfigValidationError::EntryNotFound(
                            "native remote key provider".to_string(),
                        ),
                    )?;
                    Arc::new(RemoteSecureElementKeyProvider::new(native_storage))
                }
            };
        storages.insert(name.to_owned(), storage);
    }

    for (key, value) in config.key_storage.iter_mut() {
        if let Some(entity) = storages.get(key) {
            value.capabilities = Some(json!(entity.get_capabilities()));
        }
    }

    Ok(Arc::new(KeyProviderImpl { storages }))
}
