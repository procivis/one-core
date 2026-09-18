use std::sync::Arc;

use shared_types::{InstanceId, OrganisationId};

use super::WalletAttestationRepository;
use super::error::DataLayerError;
use crate::model::instance::{
    Instance, InstanceList, InstanceListQuery, InstanceRole, UpdateInstanceRequest,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::relation::AsyncVecLoader;
use crate::model::wallet_attestation::{WalletAttestation, WalletAttestationFilterValue};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait InstanceRepository: Send + Sync {
    async fn create(&self, request: Instance) -> Result<InstanceId, DataLayerError>;

    async fn get(&self, id: &InstanceId) -> Result<Instance, DataLayerError>;

    async fn get_by_role(
        &self,
        role: InstanceRole,
        organisation_id: OrganisationId,
    ) -> Result<Option<Instance>, DataLayerError>;

    async fn update(
        &self,
        id: &InstanceId,
        request: UpdateInstanceRequest,
    ) -> Result<(), DataLayerError>;

    async fn list(&self, query: InstanceListQuery) -> Result<InstanceList, DataLayerError>;

    async fn delete(&self, id: &InstanceId) -> Result<(), DataLayerError>;
}

pub struct InstanceWalletAttestationsLoader {
    pub id: InstanceId,
    pub wallet_attestation_repository: Arc<dyn WalletAttestationRepository>,
}

#[async_trait::async_trait]
impl AsyncVecLoader<WalletAttestation> for InstanceWalletAttestationsLoader {
    async fn load(&self) -> Result<Vec<WalletAttestation>, DataLayerError> {
        Ok(self
            .wallet_attestation_repository
            .get_attestations(ListQuery {
                filtering: Some(WalletAttestationFilterValue::Instance(self.id).condition()),
                ..Default::default()
            })
            .await?
            .values)
    }
}
