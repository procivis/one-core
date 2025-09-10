use async_trait;
use one_crypto::SignerError;
use shared_types::KeyId;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::{Key, PrivateKeyJwk};
use crate::provider::key_algorithm::key::KeyHandle;

pub mod azure_vault;
pub mod error;
pub mod internal;
pub mod model;
pub mod pkcs11;
pub mod provider;
pub mod remote_secure_element;
pub mod secure_element;

/// Generate key pairs and sign via key references.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait KeyStorage: Send + Sync {
    /// See the [API docs][ksc] for a complete list of credential format capabilities.
    ///
    /// [ksc]: https://docs.procivis.ch/api/resources/keys#key-storage-capabilities
    fn get_capabilities(&self) -> model::KeyStorageCapabilities;

    /// Generates a key pair and returns the key reference. Does not expose the private key.
    async fn generate(
        &self,
        key_id: KeyId,
        key_algorithm: KeyAlgorithmType,
    ) -> Result<model::StorageGeneratedKey, error::KeyStorageError>;

    async fn import(
        &self,
        key_id: KeyId,
        key_algorithm: KeyAlgorithmType,
        jwk: PrivateKeyJwk,
    ) -> Result<model::StorageGeneratedKey, error::KeyStorageError>;

    /// Access to key operations
    fn key_handle(&self, key: &Key) -> Result<KeyHandle, SignerError>;

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
