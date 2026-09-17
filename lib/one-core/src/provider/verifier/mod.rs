use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use dto::{VerifierProviderCapabilities, VerifierProviderRegistrationParams};
use error::VerifierProviderError;
use proc_macros::provider_mock;

use crate::provider::Provider;
use crate::service::verifier_provider::dto::VerifierProviderMetadataResponseDTO;

mod decorators;
pub mod dto;
pub mod error;
mod procivis;
pub mod provider;

#[provider_mock]
#[async_trait]
pub(crate) trait VerifierProvider: Provider + Send + Sync {
    fn get_capabilities(&self) -> VerifierProviderCapabilities;

    fn get_registration_params(
        &self,
    ) -> Result<VerifierProviderRegistrationParams, VerifierProviderError>;

    async fn get_metadata(
        &self,
    ) -> Result<VerifierProviderMetadataResponseDTO, VerifierProviderError>;

    fn config_name(&self) -> &str;
}

impl Display for dyn VerifierProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "VerifierProvider `{}`", self.config_name())
    }
}
