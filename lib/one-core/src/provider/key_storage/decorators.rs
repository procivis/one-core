use std::fmt::Display;
use std::sync::Arc;

use serde_json::Value;
use shared_types::KeyId;
use standardized_types::jwk::PrivateJwk;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::model::key::Key;
use crate::provider::Provider;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_storage::KeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::{Features, KeyStorageCapabilities, StorageGeneratedKey};
use crate::provider::provider_directory::WithDisabledDecorator;

impl WithDisabledDecorator for dyn KeyStorage {
    fn decorate(self: Arc<dyn KeyStorage>) -> Arc<dyn KeyStorage> {
        Arc::new(DisabledProvider::new(self))
    }
}

/// Functionality of disabled key storage is limited to using existing keys, but not generate new ones.
#[async_trait::async_trait]
impl<T: KeyStorage + Display + ?Sized> KeyStorage for DisabledProvider<T> {
    fn get_capabilities(&self) -> KeyStorageCapabilities {
        let mut capabilities = self.inner().get_capabilities();
        // drop features related to generating new keys
        capabilities.features.retain(|f| f == &Features::Exportable);
        capabilities
    }

    fn config_name(&self) -> String {
        KeyStorage::config_name(self.inner())
    }

    async fn generate(
        &self,
        _key_id: KeyId,
        _key_algorithm: KeyAlgorithmType,
        _params: Value,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        self.disabled_error()
    }

    async fn import(
        &self,
        _key_id: KeyId,
        _key_algorithm: KeyAlgorithmType,
        _jwk: PrivateJwk,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        self.disabled_error()
    }

    fn key_handle(&self, key: &Key) -> Result<KeyHandle, KeyStorageError> {
        self.inner().key_handle(key)
    }

    async fn generate_attestation_key(
        &self,
        _key_id: KeyId,
        _nonce: Option<String>,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        self.disabled_error()
    }

    async fn generate_attestation(
        &self,
        key: &Key,
        nonce: Option<String>,
    ) -> Result<Vec<String>, KeyStorageError> {
        self.inner().generate_attestation(key, nonce).await
    }

    async fn sign_with_attestation_key(
        &self,
        key: &Key,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStorageError> {
        self.inner().sign_with_attestation_key(key, data).await
    }
}

pub(super) struct CapabilityCheckedKeyStorage {
    pub inner: Arc<dyn KeyStorage>,
}

impl Provider for CapabilityCheckedKeyStorage {
    fn capabilities(&self) -> Option<Value> {
        self.inner.capabilities()
    }
}

#[async_trait::async_trait]
impl KeyStorage for CapabilityCheckedKeyStorage {
    fn get_capabilities(&self) -> KeyStorageCapabilities {
        self.inner.get_capabilities()
    }

    fn config_name(&self) -> String {
        self.inner.config_name()
    }

    async fn generate(
        &self,
        _key_id: KeyId,
        key_algorithm: KeyAlgorithmType,
        params: Value,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        if !self.get_capabilities().algorithms.contains(&key_algorithm) {
            return Err(KeyStorageError::UnsupportedKeyType {
                key_type: key_algorithm.to_string(),
            });
        }
        self.inner.generate(_key_id, key_algorithm, params).await
    }

    async fn import(
        &self,
        key_id: KeyId,
        key_algorithm: KeyAlgorithmType,
        jwk: PrivateJwk,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        let capabilities = self.get_capabilities();
        if !capabilities.features.contains(&Features::Importable) {
            return Err(KeyStorageError::UnsupportedFeature {
                feature: Features::Importable,
            });
        }
        if !capabilities.algorithms.contains(&key_algorithm) {
            return Err(KeyStorageError::UnsupportedKeyType {
                key_type: key_algorithm.to_string(),
            });
        }
        self.inner.import(key_id, key_algorithm, jwk).await
    }

    fn key_handle(&self, key: &Key) -> Result<KeyHandle, KeyStorageError> {
        if !self.get_capabilities().algorithms.contains(
            &key.key_algorithm_type()
                .error_while("getting key algorithm type")?,
        ) {
            return Err(KeyStorageError::UnsupportedKeyType {
                key_type: key.key_type.to_string(),
            });
        }
        self.inner.key_handle(key)
    }

    async fn generate_attestation_key(
        &self,
        key_id: KeyId,
        nonce: Option<String>,
    ) -> Result<StorageGeneratedKey, KeyStorageError> {
        self.inner.generate_attestation_key(key_id, nonce).await
    }

    async fn generate_attestation(
        &self,
        key: &Key,
        nonce: Option<String>,
    ) -> Result<Vec<String>, KeyStorageError> {
        self.inner.generate_attestation(key, nonce).await
    }

    async fn sign_with_attestation_key(
        &self,
        key: &Key,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStorageError> {
        self.inner.sign_with_attestation_key(key, data).await
    }
}

#[cfg(test)]
mod test {
    use std::assert_matches;
    use std::sync::Arc;

    use assert2::let_assert;
    use standardized_types::jwk::{PrivateJwk, PrivateJwkEc};
    use uuid::Uuid;

    use super::*;
    use crate::config::core_config::KeyAlgorithmType;
    use crate::provider::key_storage::error::KeyStorageError;
    use crate::provider::key_storage::model::KeyStorageCapabilities;
    use crate::provider::key_storage::{KeyStorage, MockKeyStorage};

    #[tokio::test]
    async fn test_generate_unsupported() {
        let mut inner = MockKeyStorage::new();
        inner
            .expect_get_capabilities()
            .returning(|| KeyStorageCapabilities {
                features: vec![],
                algorithms: vec![],
            });
        let inner: Arc<dyn KeyStorage> = Arc::new(inner);

        let provider = CapabilityCheckedKeyStorage { inner };

        let result = provider
            .generate(
                Uuid::new_v4().into(),
                KeyAlgorithmType::MlDsa,
                serde_json::json!({}),
            )
            .await;
        let_assert!(Err(error) = result);
        assert_matches!(error, KeyStorageError::UnsupportedKeyType { .. });
    }

    #[tokio::test]
    async fn test_import_unsupported() {
        let mut inner = MockKeyStorage::new();
        inner
            .expect_get_capabilities()
            .returning(|| KeyStorageCapabilities {
                features: vec![],
                algorithms: vec![],
            });
        let inner: Arc<dyn KeyStorage> = Arc::new(inner);

        let provider = CapabilityCheckedKeyStorage { inner };

        let result = provider
            .import(
                Uuid::new_v4().into(),
                KeyAlgorithmType::Ecdsa,
                PrivateJwk::Okp(PrivateJwkEc {
                    r#use: None,
                    kid: Some("13ae667d-392b-4c00-8896-079909fe85d7".to_string()),
                    crv: "P-256".to_string(),
                    x: "r1U6-8dqlyj-_CwYft6kxx9MCfInQYCoUwKiP579c3w".to_string(),
                    y: Some("u_EMmvFmfsUjDmDY2kBhZPK0tyycAylkoY-PLAUD1WU".to_string()),
                    d: "_M90X3GfBZoFDBZHZsMQszc2a92dCorIJBlytnmkKEM".into(),
                }),
            )
            .await;
        let_assert!(Err(error) = result);
        assert_matches!(error, KeyStorageError::UnsupportedFeature { .. });
    }
}
