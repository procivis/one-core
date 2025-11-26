use std::sync::Arc;

use one_core::model::holder_wallet_unit::{
    CreateHolderWalletUnitRequest, HolderWalletUnit, HolderWalletUnitRelations,
};
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use one_core::repository::holder_wallet_unit_repository::HolderWalletUnitRepository;
use shared_types::{HolderWalletUnitId, WalletUnitId};
use uuid::Uuid;

pub struct HolderWalletUnitsDB {
    repository: Arc<dyn HolderWalletUnitRepository>,
}

#[derive(Default)]
pub struct TestHolderWalletUnit {
    pub status: Option<WalletUnitStatus>,
    pub wallet_provider_type: Option<WalletProviderType>,
    pub wallet_provider_name: Option<String>,
    pub wallet_provider_url: Option<String>,
    pub provider_wallet_unit_id: Option<WalletUnitId>,
}

impl HolderWalletUnitsDB {
    pub fn new(repository: Arc<dyn HolderWalletUnitRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        organisation: Organisation,
        authentication_key: Key,
        test_holder_wallet_unit: TestHolderWalletUnit,
    ) -> HolderWalletUnit {
        let wallet_unit = CreateHolderWalletUnitRequest {
            id: Uuid::new_v4().into(),
            status: test_holder_wallet_unit
                .status
                .unwrap_or(WalletUnitStatus::Active),
            wallet_provider_type: test_holder_wallet_unit
                .wallet_provider_type
                .unwrap_or(WalletProviderType::ProcivisOne),
            wallet_provider_name: test_holder_wallet_unit
                .wallet_provider_name
                .unwrap_or("PROCIVIS_ONE".to_string()),
            wallet_provider_url: test_holder_wallet_unit
                .wallet_provider_url
                .unwrap_or("https://wallet.provider".to_string()),
            organisation,
            authentication_key,
            provider_wallet_unit_id: test_holder_wallet_unit
                .provider_wallet_unit_id
                .unwrap_or(Uuid::new_v4().into()),
        };

        let id = self
            .repository
            .create_holder_wallet_unit(wallet_unit)
            .await
            .unwrap();

        self.repository
            .get_holder_wallet_unit(&id, &HolderWalletUnitRelations::default())
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn get(
        &self,
        wallet_unit_id: impl Into<HolderWalletUnitId>,
        relations: &HolderWalletUnitRelations,
    ) -> Option<HolderWalletUnit> {
        self.repository
            .get_holder_wallet_unit(&wallet_unit_id.into(), relations)
            .await
            .unwrap()
    }
}
