use std::fmt::Display;
use std::sync::Arc;

use crate::error::NestedError;
use crate::provider::provider_directory::ProviderError;

pub mod blob_storage;
pub mod caching_loader;
pub mod credential_formatter;
pub mod data_type;
pub mod did_method;
mod disabled_provider;
pub mod document_signer;
pub mod ecosystem;
pub mod issuance_protocol;
pub mod key_algorithm;
pub mod key_security_level;
pub mod key_storage;
pub mod presentation_formatter;
pub mod provider_directory;
pub mod remote_entity_storage;
pub mod revocation;
pub mod signer;
pub mod task;
pub mod transaction_data;
pub mod trust_list_publisher;
pub mod trust_list_subscriber;
pub mod verification_protocol;
pub mod verifier;
pub mod wallet;

/// Trait for provider implementations. Useful for core bootstrapping and decorating.
pub trait Provider {
    fn capabilities(&self) -> Option<serde_json::Value>;

    /// Whether the provider is enabled
    fn enabled(&self) -> bool {
        true
    }
}

pub trait ProviderExt {
    /// Fails if provider not enabled
    fn ensure_enabled(&self) -> Result<(), NestedError>;
}

impl<P: Provider + Display + ?Sized> ProviderExt for Arc<P> {
    fn ensure_enabled(&self) -> Result<(), NestedError> {
        if self.enabled() {
            Ok(())
        } else {
            Err(ProviderError::ProviderDisabled {
                provider: self.to_string(),
            }
            .into())
        }
    }
}
