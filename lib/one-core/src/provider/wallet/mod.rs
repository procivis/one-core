use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use dto::{CreatedAttestation, WalletProviderCapabilities};
use error::WalletProviderError;
use proc_macros::provider_mock;
use shared_types::IdentifierId;

use crate::model::managed_instance::ManagedInstance;
use crate::provider::Provider;
use crate::service::managed_instance::dto::{
    IssueWiaRequestDTO, IssueWuaRequestDTO, ProviderRegistrationParams,
    WalletProviderMetadataResponseDTO,
};

mod decorators;
pub mod dto;
pub mod error;
mod procivis;
pub mod provider;

#[provider_mock]
#[async_trait]
pub(crate) trait WalletProvider: Provider + Send + Sync {
    fn get_capabilities(&self) -> WalletProviderCapabilities;

    async fn issue_instance_attestation(
        &self,
        request: IssueWiaRequestDTO,
        issuer: IdentifierId,
        managed_instance: &ManagedInstance,
    ) -> Result<CreatedAttestation, WalletProviderError>;

    async fn issue_key_attestation(
        &self,
        request: IssueWuaRequestDTO,
        issuer: IdentifierId,
        managed_instance: &ManagedInstance,
    ) -> Result<CreatedAttestation, WalletProviderError>;

    fn get_registration_params(&self) -> Result<ProviderRegistrationParams, WalletProviderError>;

    async fn get_metadata(&self) -> Result<WalletProviderMetadataResponseDTO, WalletProviderError>;

    fn config_name(&self) -> &str;
}

impl Display for dyn WalletProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "WalletProvider `{}`", self.config_name())
    }
}
