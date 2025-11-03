use std::ops::Sub;
use std::sync::Arc;

use one_core::model::holder_wallet_unit::{HolderWalletUnit, HolderWalletUnitRelations};
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use one_core::repository::holder_wallet_unit_repository::HolderWalletUnitRepository;
use shared_types::{HolderWalletUnitId, WalletUnitId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub struct HolderWalletUnitsDB {
    #[allow(unused)]
    repository: Arc<dyn HolderWalletUnitRepository>,
}

#[derive(Default)]
pub struct TestHolderWalletUnit {
    pub last_modified: Option<OffsetDateTime>,
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
        let six_hours_ago = OffsetDateTime::now_utc().sub(Duration::days(1));

        let wallet_unit = HolderWalletUnit {
            id: Uuid::new_v4().into(),
            created_date: six_hours_ago,
            last_modified: test_holder_wallet_unit
                .last_modified
                .unwrap_or(six_hours_ago),
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
            organisation: Some(organisation),
            authentication_key: Some(authentication_key),
            provider_wallet_unit_id: test_holder_wallet_unit
                .provider_wallet_unit_id
                .unwrap_or(Uuid::new_v4().into()),
            wallet_unit_attestations: None,
        };

        self.repository
            .create_holder_wallet_unit(wallet_unit.clone())
            .await
            .unwrap();

        wallet_unit
    }

    #[allow(unused)]
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
