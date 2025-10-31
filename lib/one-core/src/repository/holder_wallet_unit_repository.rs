use shared_types::HolderWalletUnitId;

use crate::model::holder_wallet_unit::{
    CreateHolderWalletUnitRequest, HolderWalletUnit, HolderWalletUnitRelations,
    UpdateHolderWalletUnitRequest,
};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait HolderWalletUnitRepository: Send + Sync {
    async fn create_holder_wallet_unit(
        &self,
        request: CreateHolderWalletUnitRequest,
    ) -> Result<HolderWalletUnitId, DataLayerError>;

    async fn get_holder_wallet_unit(
        &self,
        id: &HolderWalletUnitId,
        relations: &HolderWalletUnitRelations,
    ) -> Result<Option<HolderWalletUnit>, DataLayerError>;

    async fn update_holder_wallet_unit(
        &self,
        id: &HolderWalletUnitId,
        request: UpdateHolderWalletUnitRequest,
    ) -> Result<(), DataLayerError>;
}
