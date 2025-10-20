pub mod dto;
pub mod error;
pub mod http_client;

use shared_types::WalletUnitId;

use crate::provider::wallet_provider_client::dto::RefreshWalletUnitResponse;
use crate::provider::wallet_provider_client::error::WalletProviderClientError;
use crate::service::wallet_provider::dto::{
    ActivateWalletUnitRequestDTO, ActivateWalletUnitResponseDTO, RefreshWalletUnitRequestDTO,
    RegisterWalletUnitRequestDTO, RegisterWalletUnitResponseDTO,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait WalletProviderClient: Send + Sync {
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
    ) -> Result<ActivateWalletUnitResponseDTO, WalletProviderClientError>;

    async fn refresh(
        &self,
        wallet_provider_url: &str,
        wallet_unit_id: WalletUnitId,
        request: RefreshWalletUnitRequestDTO,
    ) -> Result<RefreshWalletUnitResponse, WalletProviderClientError>;
}
