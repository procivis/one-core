use std::ops::Sub;
use std::sync::Arc;

use one_core::model::instance::{InstanceRole, InstanceStatus};
use one_core::model::managed_instance::{
    ManagedInstance, ManagedInstanceList, ManagedInstanceListQuery, ManagedInstanceOs,
    UpdateManagedInstanceRequest,
};
use one_core::model::managed_instance_attestation::ManagedInstanceAttestation;
use one_core::model::organisation::Organisation;
use one_core::repository::error::DataLayerError;
use one_core::repository::managed_instance_repository::ManagedInstanceRepository;
use shared_types::{ManagedInstanceId, RevocationListEntryId};
use standardized_types::jwk::PublicJwk;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub struct ManagedInstancesDB {
    repository: Arc<dyn ManagedInstanceRepository>,
}

#[derive(Default)]
pub struct TestWalletInstance {
    pub id: Option<ManagedInstanceId>,
    pub name: Option<String>,
    pub nonce: Option<String>,
    pub last_modified: Option<OffsetDateTime>,
    pub public_key: Option<PublicJwk>,
    pub status: Option<InstanceStatus>,
    pub last_issuance: Option<Option<OffsetDateTime>>,
    pub attestations: Option<Vec<ManagedInstanceAttestation>>,
    pub user_sub: Option<String>,
    pub role: Option<InstanceRole>,
    pub provider: Option<String>,
    pub verifier_csr: Option<String>,
    pub os: Option<ManagedInstanceOs>,
    pub verifier_signature_ids: Option<Vec<RevocationListEntryId>>,
}

impl ManagedInstancesDB {
    pub fn new(repository: Arc<dyn ManagedInstanceRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        organisation: Organisation,
        test_wallet_instance: TestWalletInstance,
    ) -> ManagedInstance {
        let six_hours_ago = one_core::clock::now_utc().sub(Duration::days(1));

        let wallet_instance = ManagedInstance {
            id: test_wallet_instance
                .id
                .unwrap_or_else(|| Uuid::new_v4().into()),
            name: test_wallet_instance
                .name
                .unwrap_or("test_wallet".to_string()),
            created_date: six_hours_ago,
            last_modified: test_wallet_instance.last_modified.unwrap_or(six_hours_ago),
            os: test_wallet_instance
                .os
                .unwrap_or(ManagedInstanceOs::Android),
            status: test_wallet_instance
                .status
                .unwrap_or(InstanceStatus::Active),
            provider: test_wallet_instance
                .provider
                .unwrap_or("PROCIVIS_ONE".to_string()),
            role: test_wallet_instance.role.unwrap_or(InstanceRole::Wallet),
            authentication_key_jwk: test_wallet_instance.public_key,
            last_issuance: test_wallet_instance
                .last_issuance
                .unwrap_or(Some(six_hours_ago)),
            nonce: test_wallet_instance.nonce,
            user_nonce: None,
            user_sub: test_wallet_instance.user_sub,
            verifier_csr: test_wallet_instance.verifier_csr,
            verifier_signature_ids: test_wallet_instance.verifier_signature_ids,
            organisation: organisation.into(),
            attestations: test_wallet_instance.attestations.unwrap_or_default().into(),
        };

        self.repository
            .create(wallet_instance.clone())
            .await
            .unwrap();

        wallet_instance
    }

    pub async fn list(&self, query: ManagedInstanceListQuery) -> ManagedInstanceList {
        self.repository.get_list(query).await.unwrap()
    }

    pub async fn get(
        &self,
        wallet_instance_id: impl Into<ManagedInstanceId>,
    ) -> Option<ManagedInstance> {
        match self.repository.get(&wallet_instance_id.into()).await {
            Ok(instance) => Some(instance),
            Err(DataLayerError::EntityNotFound { .. }) => None,
            Err(err) => panic!("get managed instance: {err}"),
        }
    }

    #[allow(unused)]
    pub async fn update(
        &self,
        wallet_instance_id: impl Into<ManagedInstanceId>,
        request: UpdateManagedInstanceRequest,
    ) -> () {
        self.repository
            .update(&wallet_instance_id.into(), request)
            .await
            .unwrap()
    }
}
