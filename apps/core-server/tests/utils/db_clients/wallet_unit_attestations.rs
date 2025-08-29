use std::ops::Add;
use std::sync::Arc;

use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use one_core::model::wallet_unit_attestation::{
    WalletUnitAttestation, WalletUnitAttestationRelations,
};
use one_core::repository::wallet_unit_attestation_repository::WalletUnitAttestationRepository;
use shared_types::{OrganisationId, WalletUnitAttestationId, WalletUnitId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub struct WalletUnitAttestationsDB {
    repository: Arc<dyn WalletUnitAttestationRepository>,
}

#[derive(Default)]
pub struct TestWalletUnitAttestation {
    pub id: Option<WalletUnitAttestationId>,
    pub expiration_date: Option<OffsetDateTime>,
    pub status: Option<WalletUnitStatus>,
    pub attestation: Option<String>,
    pub wallet_unit_id: Option<WalletUnitId>,
    pub wallet_provider_url: Option<String>,

    // Relations:
    pub organisation: Option<Organisation>,
    pub key: Option<Key>,
}

impl WalletUnitAttestationsDB {
    pub fn new(repository: Arc<dyn WalletUnitAttestationRepository>) -> Self {
        Self { repository }
    }

    pub async fn get_by_organisation(
        &self,
        organisation_id: &OrganisationId,
    ) -> Option<WalletUnitAttestation> {
        self.repository
            .get_wallet_unit_attestation_by_organisation(
                organisation_id,
                &WalletUnitAttestationRelations::default(),
            )
            .await
            .unwrap()
    }

    pub async fn create(
        &self,
        test_wallet_unit_attestation: TestWalletUnitAttestation,
    ) -> WalletUnitAttestation {
        let now = OffsetDateTime::now_utc();
        let attestation = WalletUnitAttestation {
            id: test_wallet_unit_attestation
                .id
                .unwrap_or(Uuid::new_v4().into()),
            created_date: now,
            last_modified: now,
            expiration_date: test_wallet_unit_attestation
                .expiration_date
                .unwrap_or(now.add(Duration::minutes(180))),
            status: test_wallet_unit_attestation
                .status
                .unwrap_or(WalletUnitStatus::Active),
            attestation: test_wallet_unit_attestation
                .attestation
                .unwrap_or("some_invalid_attestation".to_string()),
            wallet_unit_id: test_wallet_unit_attestation
                .wallet_unit_id
                .unwrap_or(Uuid::new_v4().into()),
            wallet_provider_url: test_wallet_unit_attestation
                .wallet_provider_url
                .unwrap_or("http://localhost:8080".to_string()),
            wallet_provider_type: WalletProviderType::ProcivisOne,
            wallet_provider_name: "PROCIVIS_ONE".to_string(),
            organisation: test_wallet_unit_attestation.organisation,
            key: test_wallet_unit_attestation.key,
        };
        self.repository
            .create_wallet_unit_attestation(attestation.clone())
            .await
            .unwrap();

        attestation
    }
}
