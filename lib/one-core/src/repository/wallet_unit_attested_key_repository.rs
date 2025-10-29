use shared_types::{WalletUnitAttestedKeyId, WalletUnitId};

use crate::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyRelations,
};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait WalletUnitAttestedKeyRepository: Send + Sync {
    async fn create_attested_key(
        &self,
        request: WalletUnitAttestedKey,
    ) -> Result<WalletUnitAttestedKeyId, DataLayerError>;

    async fn update_attested_key(
        &self,
        request: WalletUnitAttestedKey,
    ) -> Result<(), DataLayerError>;

    async fn get_attested_key(
        &self,
        id: &WalletUnitAttestedKeyId,
        relations: &WalletUnitAttestedKeyRelations,
    ) -> Result<Option<WalletUnitAttestedKey>, DataLayerError>;

    async fn get_by_wallet_unit_id(
        &self,
        id: WalletUnitId,
        relations: &WalletUnitAttestedKeyRelations,
    ) -> Result<Vec<WalletUnitAttestedKey>, DataLayerError>;
}
