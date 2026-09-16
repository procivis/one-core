use std::fmt::Display;
use std::sync::Arc;

use shared_types::IdentifierId;

use super::WalletProvider;
use super::dto::{
    CreatedAttestation, WalletProviderCapabilities, WalletProviderRegistrationParams,
};
use super::error::WalletProviderError;
use crate::model::managed_instance::ManagedInstance;
use crate::provider::Provider;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::provider_directory::WithDisabledDecorator;
use crate::service::managed_instance::dto::{
    IssueWiaRequestDTO, IssueWuaRequestDTO, WalletProviderMetadataResponseDTO,
};

impl WithDisabledDecorator for dyn WalletProvider {
    fn decorate(self: Arc<dyn WalletProvider>) -> Arc<dyn WalletProvider> {
        Arc::new(DisabledProvider::new(self))
    }
}

#[async_trait::async_trait]
impl<T: Provider + WalletProvider + Display + ?Sized> WalletProvider for DisabledProvider<T> {
    async fn issue_instance_attestation(
        &self,
        _request: IssueWiaRequestDTO,
        _issuer: IdentifierId,
        _managed_instance: &ManagedInstance,
    ) -> Result<CreatedAttestation, WalletProviderError> {
        self.disabled_error()
    }

    async fn issue_key_attestation(
        &self,
        _request: IssueWuaRequestDTO,
        _issuer: IdentifierId,
        _managed_instance: &ManagedInstance,
    ) -> Result<CreatedAttestation, WalletProviderError> {
        self.disabled_error()
    }

    fn get_registration_params(
        &self,
    ) -> Result<WalletProviderRegistrationParams, WalletProviderError> {
        self.disabled_error()
    }

    async fn get_metadata(&self) -> Result<WalletProviderMetadataResponseDTO, WalletProviderError> {
        self.disabled_error()
    }

    fn get_capabilities(&self) -> WalletProviderCapabilities {
        self.inner().get_capabilities()
    }

    fn config_name(&self) -> &str {
        self.inner().config_name()
    }
}
