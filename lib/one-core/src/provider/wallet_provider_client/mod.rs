pub mod dto;
pub mod error;
pub mod http_client;

use shared_types::WalletUnitId;

use crate::provider::wallet_provider_client::dto::IssueWalletAttestationResponse;
use crate::provider::wallet_provider_client::error::WalletProviderClientError;
use crate::service::wallet_provider::dto::{
    ActivateWalletUnitRequestDTO, IssueWalletUnitAttestationRequestDTO,
    RegisterWalletUnitRequestDTO, RegisterWalletUnitResponseDTO, WalletProviderMetadataResponseDTO,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait WalletProviderClient: Send + Sync {
    async fn get_wallet_provider_metadata(
        &self,
        wallet_provider_metadata_url: &str,
    ) -> Result<WalletProviderMetadataResponseDTO, WalletProviderClientError>;

    async fn register(
        &self,
        wallet_provider_url: &str,
        request: RegisterWalletUnitRequestDTO,
    ) -> Result<RegisterWalletUnitResponseDTO, WalletProviderClientError>;

    async fn activate(
        &self,
        wallet_provider_url: &str,
        wallet_unit_id: WalletUnitId,
        request: ActivateWalletUnitRequestDTO,
    ) -> Result<(), WalletProviderClientError>;

    async fn issue_attestation(
        &self,
        wallet_provider_url: &str,
        wallet_unit_id: WalletUnitId,
        bearer_token: &str,
        request: IssueWalletUnitAttestationRequestDTO,
    ) -> Result<IssueWalletAttestationResponse, WalletProviderClientError>;
}
