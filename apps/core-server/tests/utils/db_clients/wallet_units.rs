use std::ops::Sub;
use std::sync::Arc;

use one_core::model::key::PublicKeyJwk;
use one_core::model::wallet_unit::{
    GetWalletUnitList, WalletProviderType, WalletUnit, WalletUnitListQuery, WalletUnitOs,
    WalletUnitRelations, WalletUnitStatus,
};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::repository::wallet_unit_repository::WalletUnitRepository;
use shared_types::WalletUnitId;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub struct WalletUnitsDB {
    repository: Arc<dyn WalletUnitRepository>,
}

#[derive(Default)]
pub struct TestWalletUnit {
    pub name: Option<String>,
    pub nonce: Option<String>,
    pub last_modified: Option<OffsetDateTime>,
    pub public_key: Option<PublicKeyJwk>,
    pub status: Option<WalletUnitStatus>,
    pub last_issuance: Option<Option<OffsetDateTime>>,
}

impl WalletUnitsDB {
    pub fn new(repository: Arc<dyn WalletUnitRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(&self, test_wallet_unit: TestWalletUnit) -> WalletUnit {
        let six_hours_ago = OffsetDateTime::now_utc().sub(Duration::days(1));

        let wallet_unit = WalletUnit {
            id: Uuid::new_v4().into(),
            name: test_wallet_unit.name.unwrap_or("test_wallet".to_string()),
            created_date: six_hours_ago,
            last_modified: test_wallet_unit.last_modified.unwrap_or(six_hours_ago),
            os: WalletUnitOs::Android,
            status: test_wallet_unit.status.unwrap_or(WalletUnitStatus::Active),
            wallet_provider_type: WalletProviderType::ProcivisOne,
            wallet_provider_name: "PROCIVIS_ONE".to_string(),
            public_key: Some(
                serde_json::to_string(&test_wallet_unit.public_key.unwrap_or(random_jwk()))
                    .unwrap(),
            ),
            last_issuance: test_wallet_unit
                .last_issuance
                .unwrap_or(Some(six_hours_ago)),
            nonce: test_wallet_unit.nonce,
        };

        self.repository
            .create_wallet_unit(wallet_unit.clone())
            .await
            .unwrap();

        wallet_unit
    }

    pub async fn list(&self, query: WalletUnitListQuery) -> GetWalletUnitList {
        self.repository.get_wallet_unit_list(query).await.unwrap()
    }

    pub async fn get(
        &self,
        wallet_unit_id: impl Into<WalletUnitId>,
        relations: &WalletUnitRelations,
    ) -> Option<WalletUnit> {
        self.repository
            .get_wallet_unit(&wallet_unit_id.into(), relations)
            .await
            .unwrap()
    }
}

fn random_jwk() -> PublicKeyJwk {
    let holder_key_pair = Ecdsa.generate_key().unwrap();
    holder_key_pair.key.public_key_as_jwk().unwrap()
}
