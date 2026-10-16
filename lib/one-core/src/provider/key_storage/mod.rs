use std::fmt::{Display, Formatter};

use proc_macros::provider_mock;
use shared_types::KeyId;
use standardized_types::jwk::PrivateJwk;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::provider::Provider;
use crate::provider::key_algorithm::key::KeyHandle;

pub mod azure_vault;
mod decorators;
pub mod error;
pub mod internal;
pub mod model;
pub mod provider;
pub mod remote_secure_element;

/// Generate key pairs and sign via key references.
#[provider_mock]
#[async_trait::async_trait]
pub trait KeyStorage: Provider + Send + Sync {
    /// See the [API docs][ksc] for a complete list of credential format capabilities.
    ///
    /// [ksc]: https://docs.procivis.ch/api/resources/keys#key-storage-capabilities
    fn get_capabilities(&self) -> model::KeyStorageCapabilities;

    fn config_name(&self) -> String;

    /// Generates a key pair and returns the key reference. Does not expose the private key.
    async fn generate(
        &self,
        key_id: KeyId,
        key_algorithm: KeyAlgorithmType,
        params: serde_json::Value,
    ) -> Result<model::StorageGeneratedKey, error::KeyStorageError>;

    async fn import(
        &self,
        key_id: KeyId,
        key_algorithm: KeyAlgorithmType,
        jwk: PrivateJwk,
    ) -> Result<model::StorageGeneratedKey, error::KeyStorageError>;

    /// Access to key operations
    fn key_handle(&self, key: &Key) -> Result<KeyHandle, error::KeyStorageError>;

    // Generate hardware bound key for wallet unit attestations
    async fn generate_attestation_key(
        &self,
        key_id: KeyId,
        nonce: Option<String>,
    ) -> Result<model::StorageGeneratedKey, error::KeyStorageError>;

    /// Generate attestation for a hardware bound key
    async fn generate_attestation(
        &self,
        key: &Key,
        nonce: Option<String>,
    ) -> Result<Vec<String>, error::KeyStorageError>;

    // Generate a signed assertion, using a hardware bound attestation key
    async fn sign_with_attestation_key(
        &self,
        key: &Key,
        data: &[u8],
    ) -> Result<Vec<u8>, error::KeyStorageError>;
}

mod csc;
pub mod secure_element;

impl Display for dyn KeyStorage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key storage `{}`", self.config_name())
    }
}
