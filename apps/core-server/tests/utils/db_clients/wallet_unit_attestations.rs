use std::ops::Add;
use std::sync::Arc;

use one_core::model::key::Key;
use one_core::model::wallet_unit_attestation::{
    WalletUnitAttestation, WalletUnitAttestationRelations,
};
use one_core::repository::wallet_unit_attestation_repository::WalletUnitAttestationRepository;
use shared_types::{HolderWalletUnitId, WalletUnitAttestationId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[allow(unused)]
pub struct WalletUnitAttestationsDB {
    #[allow(unused)]
    repository: Arc<dyn WalletUnitAttestationRepository>,
}

#[allow(unused)]
#[derive(Default)]
pub struct TestWalletUnitAttestation {
    pub id: Option<WalletUnitAttestationId>,
    pub expiration_date: Option<OffsetDateTime>,
    pub attestation: Option<String>,
    pub revocation_list_url: Option<String>,
    pub revocation_list_index: Option<i64>,
}

impl WalletUnitAttestationsDB {
    pub fn new(repository: Arc<dyn WalletUnitAttestationRepository>) -> Self {
        Self { repository }
    }

    #[allow(unused)]
    pub async fn get_by_wallet_unit(
        &self,
        holder_wallet_unit_id: &HolderWalletUnitId,
    ) -> Vec<WalletUnitAttestation> {
        self.repository
            .get_wallet_unit_attestations_by_holder_wallet_unit(
                holder_wallet_unit_id,
                &WalletUnitAttestationRelations::default(),
            )
            .await
            .unwrap()
    }

    #[allow(unused)]
    pub async fn create(
        &self,
        test_wallet_unit_attestation: TestWalletUnitAttestation,
        holder_wallet_unit_id: HolderWalletUnitId,
        attested_key: Key,
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
            attestation: test_wallet_unit_attestation
                .attestation
                .unwrap_or("some_invalid_attestation".to_string()),
            holder_wallet_unit_id,
            revocation_list_url: test_wallet_unit_attestation.revocation_list_url,
            revocation_list_index: test_wallet_unit_attestation.revocation_list_index,
            attested_key: Some(attested_key),
        };
        self.repository
            .create_wallet_unit_attestation(attestation.clone())
            .await
            .unwrap();

        attestation
    }
}
