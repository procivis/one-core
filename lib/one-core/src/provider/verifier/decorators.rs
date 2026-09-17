use std::fmt::Display;
use std::sync::Arc;

use super::VerifierProvider;
use super::dto::{VerifierProviderCapabilities, VerifierProviderRegistrationParams};
use super::error::VerifierProviderError;
use crate::provider::Provider;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::provider_directory::WithDisabledDecorator;
use crate::service::verifier_provider::dto::VerifierProviderMetadataResponseDTO;

impl WithDisabledDecorator for dyn VerifierProvider {
    fn decorate(self: Arc<dyn VerifierProvider>) -> Arc<dyn VerifierProvider> {
        Arc::new(DisabledProvider::new(self))
    }
}

#[async_trait::async_trait]
impl<T: Provider + VerifierProvider + Display + ?Sized> VerifierProvider for DisabledProvider<T> {
    fn get_capabilities(&self) -> VerifierProviderCapabilities {
        self.inner().get_capabilities()
    }

    fn get_registration_params(
        &self,
    ) -> Result<VerifierProviderRegistrationParams, VerifierProviderError> {
        self.disabled_error()
    }

    async fn get_metadata(
        &self,
    ) -> Result<VerifierProviderMetadataResponseDTO, VerifierProviderError> {
        self.disabled_error()
    }

    fn config_name(&self) -> &str {
        self.inner().config_name()
    }
}
