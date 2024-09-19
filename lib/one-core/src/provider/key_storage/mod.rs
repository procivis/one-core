use async_trait;
use shared_types::KeyId;
use zeroize::Zeroizing;

use crate::crypto::SignerError;
use crate::model::key::Key;

pub mod azure_vault;
pub mod error;
pub mod internal;
pub mod model;
pub mod pkcs11;
pub mod provider;
pub mod secure_element;

/// Generate key pairs and sign via key references.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait KeyStorage: Send + Sync {
    /// Generates a key pair and returns the key reference. Does not expose the private key.
    async fn generate(
        &self,
        key_id: Option<KeyId>,
        key_type: &str,
    ) -> Result<model::StorageGeneratedKey, error::KeyStorageError>;

    /// Sign with a private key via the key reference.
    async fn sign(&self, key: &Key, message: &[u8]) -> Result<Vec<u8>, SignerError>;

    /// Converts a private key to JWK (thus exposing it).
    ///
    /// **Use carefully.**
    ///
    /// May not be implemented for some storage providers (e.g. Azure Key Vault).
    fn secret_key_as_jwk(&self, key: &Key) -> Result<Zeroizing<String>, error::KeyStorageError>;

    #[doc = include_str!("../../../../../docs/capabilities.md")]
    ///
    /// See the [API docs][ksc] for a complete list of credential format capabilities.
    ///
    /// [ksc]: https://docs.procivis.ch/api/resources/keys#key-storage-capabilities
    fn get_capabilities(&self) -> model::KeyStorageCapabilities;
}
