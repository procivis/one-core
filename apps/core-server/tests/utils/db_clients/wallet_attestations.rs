use std::sync::Arc;

use one_core::model::key::Key;
use one_core::model::list_filter::ListFilterValue;
use one_core::model::list_query::ListQuery;
use one_core::model::wallet_attestation::{
    AttestationType, WalletAttestation, WalletAttestationFilterValue,
};
use one_core::repository::wallet_attestation_repository::WalletAttestationRepository;
use one_dto_mapper::convert_inner;
use shared_types::{InstanceId, WalletAttestationId};
use time::OffsetDateTime;
use uuid::Uuid;

pub struct WalletAttestationsDB {
    repository: Arc<dyn WalletAttestationRepository>,
}

#[derive(Default)]
pub struct TestWalletAttestation {
    pub id: Option<WalletAttestationId>,
    pub expiration_date: Option<OffsetDateTime>,
    pub attestation: Option<String>,
    pub attested_key: Option<Key>,
}

impl WalletAttestationsDB {
    pub fn new(repository: Arc<dyn WalletAttestationRepository>) -> Self {
        Self { repository }
    }

    #[expect(unused)]
    pub async fn get_by_wallet_instance(&self, instance_id: &InstanceId) -> Vec<WalletAttestation> {
        self.repository
            .get_attestations(ListQuery {
                filtering: Some(WalletAttestationFilterValue::Instance(*instance_id).condition()),
                ..Default::default()
            })
            .await
            .unwrap()
            .values
    }

    #[expect(unused)]
    pub async fn create(
        &self,
        r#type: AttestationType,
        holder_wallet_instance_id: InstanceId,
        params: TestWalletAttestation,
    ) -> WalletAttestation {
        let now = one_core::clock::now_utc();
        let attestation = WalletAttestation {
            id: params.id.unwrap_or(Uuid::new_v4().into()),
            r#type,
            created_date: now,
            last_modified: now,
            expiration_date: params.expiration_date,
            attestation: params
                .attestation
                .unwrap_or("some_invalid_attestation".to_string()),
            instance_id: holder_wallet_instance_id,
            attested_key: convert_inner(params.attested_key),
        };
        self.repository.create(attestation.clone()).await.unwrap();

        attestation
    }
}
