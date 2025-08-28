use std::sync::Arc;

use one_core::model::wallet_unit::{WalletProviderType, WalletUnit, WalletUnitStatus};
use one_core::repository::wallet_unit_repository::WalletUnitRepository;
use shared_types::WalletUnitId;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

pub struct WalletUnitsDB {
    repository: Arc<dyn WalletUnitRepository>,
}

impl WalletUnitsDB {
    pub fn new(repository: Arc<dyn WalletUnitRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(&self) -> WalletUnit {
        self.create_with_name("test_wallet").await
    }

    pub async fn create_with_name(&self, name: &str) -> WalletUnit {
        let id: WalletUnitId = Uuid::new_v4().into();
        let now = get_dummy_date();

        // Generate unique public key to avoid constraint violations
        let unique_suffix = id.to_string();

        let wallet_unit = WalletUnit {
            id,
            created_date: now,
            last_modified: now,
            last_issuance: now,
            name: name.to_string(),
            os: "ANDROID".to_string(),
            status: WalletUnitStatus::Active,
            wallet_provider_type: WalletProviderType::ProcivisOne,
            wallet_provider_name: "Test Provider Name".to_string(),
            public_key: format!("test_public_key_{unique_suffix}"),
        };

        self.repository
            .create_wallet_unit(wallet_unit.clone())
            .await
            .unwrap();

        wallet_unit
    }

    pub async fn create_revoked(&self) -> WalletUnit {
        let id: WalletUnitId = Uuid::new_v4().into();
        let now = get_dummy_date();

        // Generate unique public key to avoid constraint violations
        let unique_suffix = id.to_string();

        let wallet_unit = WalletUnit {
            id,
            created_date: now,
            last_modified: now,
            last_issuance: now,
            name: "revoked_wallet".to_string(),
            os: "IOS".to_string(),
            status: WalletUnitStatus::Revoked,
            wallet_provider_type: WalletProviderType::ProcivisOne,
            wallet_provider_name: "Test Provider Name".to_string(),
            public_key: format!("test_public_key_{unique_suffix}"),
        };

        self.repository
            .create_wallet_unit(wallet_unit.clone())
            .await
            .unwrap();

        wallet_unit
    }
}
