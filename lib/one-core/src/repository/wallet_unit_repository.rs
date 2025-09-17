use shared_types::WalletUnitId;

use super::error::DataLayerError;
use crate::model::wallet_unit::{
    GetWalletUnitList, UpdateWalletUnitRequest, WalletUnit, WalletUnitListQuery,
    WalletUnitRelations,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait WalletUnitRepository: Send + Sync {
    async fn create_wallet_unit(&self, request: WalletUnit)
    -> Result<WalletUnitId, DataLayerError>;

    async fn get_wallet_unit(
        &self,
        id: &WalletUnitId,
        relations: &WalletUnitRelations,
    ) -> Result<Option<WalletUnit>, DataLayerError>;

    async fn get_wallet_unit_list(
        &self,
        query_params: WalletUnitListQuery,
    ) -> Result<GetWalletUnitList, DataLayerError>;

    async fn update_wallet_unit(
        &self,
        id: &WalletUnitId,
        request: UpdateWalletUnitRequest,
    ) -> Result<(), DataLayerError>;

    async fn delete_wallet_unit(&self, id: &WalletUnitId) -> Result<(), DataLayerError>;
}
