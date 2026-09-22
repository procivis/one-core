//! Key storage provider.

use std::sync::Arc;

use super::KeyStorage;
use super::azure_vault::AzureVaultKeyProvider;
use super::decorators::CapabilityCheckedKeyStorage;
use super::internal::InternalKeyProvider;
use super::remote_secure_element::RemoteSecureElementKeyProvider;
use super::secure_element::{NativeKeyStorage, SecureElementKeyProvider};
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, Fields, KeyAlgorithmType, KeyStorageType};
use crate::error::{ContextWithErrorCode, NestedError};
use crate::model::key::Key;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::csc::CscClient;
use crate::proto::http_client::HttpClient;
use crate::provider::credential_formatter::model::{AuthenticationFn, SignatureProvider};
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::sign8::Sign8KeyProvider;
use crate::provider::provider_directory::{InitializationError, ProviderDirectory};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait KeyProvider: Send + Sync {
    fn get_key_storage(&self, key_provider_id: &str) -> Result<Arc<dyn KeyStorage>, NestedError>;

    fn get_signature_provider(
        &self,
        key: &Key,
        jwk_key_id: Option<String>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Result<AuthenticationFn, NestedError> {
        let key_handle = self
            .get_key_storage(&key.storage_type)
            .error_while("getting key storage for signature provider")?
            .key_handle(key)
            .error_while("getting key handle for signature provider")?;

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
    ) -> Result<AuthenticationFn, NestedError> {
        let key_storage = self
            .get_key_storage(&key.storage_type)
            .error_while("getting key storage for attestation signature provider")?;

        Ok(Box::new(AttestationSignatureProvider {
            key: key.to_owned(),
            key_storage,
            jwk_key_id,
            key_algorithm_provider,
        }))
    }
}

impl KeyProvider for ProviderDirectory<String, Fields<KeyStorageType>, dyn KeyStorage> {
    fn get_key_storage(&self, key_provider_id: &str) -> Result<Arc<dyn KeyStorage>, NestedError> {
        self.provider(key_provider_id)
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
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        Ok(self.key_handle.sign(message).await.error_while("signing")?)
    }

    fn get_key_id(&self) -> Option<String> {
        self.jwk_key_id.to_owned()
    }

    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, KeyAlgorithmError> {
        self.key
            .key_algorithm_type()
            .error_while("getting key algorithm type")
            .map_err(Into::into)
    }

    fn jose_alg(&self) -> Result<String, KeyAlgorithmError> {
        Ok(self
            .key_algorithm_provider
            .key_algorithm_from_key(&self.key)
            .error_while("getting key algorithm")?
            .issuance_jose_alg_id())
    }

    fn get_public_key(&self) -> Vec<u8> {
        self.key.public_key.to_owned()
    }
}

#[async_trait::async_trait]
impl SignatureProvider for AttestationSignatureProvider {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        Ok(self
            .key_storage
            .sign_with_attestation_key(&self.key, message)
            .await
            .error_while("signing with attestation key")?)
    }

    fn get_key_id(&self) -> Option<String> {
        self.jwk_key_id.to_owned()
    }

    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, KeyAlgorithmError> {
        self.key
            .key_algorithm_type()
            .error_while("getting key algorithm")
            .map_err(Into::into)
    }

    fn jose_alg(&self) -> Result<String, KeyAlgorithmError> {
        Ok(self
            .key_algorithm_provider
            .key_algorithm_from_key(&self.key)
            .error_while("getting key algorithm")?
            .issuance_jose_alg_id())
    }

    fn get_public_key(&self) -> Vec<u8> {
        self.key.public_key.to_owned()
    }
}

pub(crate) fn key_provider_from_config(
    config: &mut CoreConfig,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    client: Arc<dyn HttpClient>,
    csc_client: Arc<dyn CscClient>,
    certificate_validator: Arc<dyn CertificateValidator>,
    native_secure_element: Option<Arc<dyn NativeKeyStorage>>,
    remote_secure_element: Option<Arc<dyn NativeKeyStorage>>,
) -> Result<Arc<dyn KeyProvider>, ConfigValidationError> {
    let initializer = move |name: &str, field: &Fields<KeyStorageType>| {
        initialize_provider(
            name,
            field,
            key_algorithm_provider.clone(),
            client.clone(),
            csc_client.clone(),
            certificate_validator.clone(),
            native_secure_element.clone(),
            remote_secure_element.clone(),
        )
    };
    let directory = ProviderDirectory::initialize(config.key_storage.iter_mut(), initializer)
        .error_while("initializing key storage providers")?;
    Ok(Arc::new(directory))
}

#[expect(clippy::too_many_arguments)]
fn initialize_provider(
    name: &str,
    field: &Fields<KeyStorageType>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    client: Arc<dyn HttpClient>,
    csc_client: Arc<dyn CscClient>,
    certificate_validator: Arc<dyn CertificateValidator>,
    native_secure_element: Option<Arc<dyn NativeKeyStorage>>,
    remote_secure_element: Option<Arc<dyn NativeKeyStorage>>,
) -> Result<Arc<dyn KeyStorage>, InitializationError> {
    let provider: Arc<dyn KeyStorage> = match field.r#type {
        KeyStorageType::Internal => Arc::new(InternalKeyProvider::new(
            name,
            key_algorithm_provider,
            field.merge_fields(),
        )?),
        KeyStorageType::AzureVault => Arc::new(AzureVaultKeyProvider::new(
            name,
            field.merge_fields(),
            client,
        )?),
        KeyStorageType::SecureElement => {
            let native_storage = native_secure_element.ok_or(
                InitializationError::MissingDependency("native key provider".to_string()),
            )?;
            Arc::new(SecureElementKeyProvider::new(
                name,
                native_storage,
                field.merge_fields(),
            )?)
        }
        KeyStorageType::RemoteSecureElement => {
            let native_storage = remote_secure_element.ok_or(
                InitializationError::MissingDependency("native remote key provider".to_string()),
            )?;
            Arc::new(RemoteSecureElementKeyProvider::new(name, native_storage))
        }
        KeyStorageType::Sign8 => Arc::new(Sign8KeyProvider::new(
            name.to_string(),
            csc_client,
            client,
            certificate_validator,
            field.merge_fields(),
        )?),
    };
    Ok(Arc::new(CapabilityCheckedKeyStorage { inner: provider }))
}
