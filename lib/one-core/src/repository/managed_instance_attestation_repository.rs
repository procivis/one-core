use std::sync::Arc;

use shared_types::{ManagedInstanceAttestationId, ManagedInstanceId};

use crate::model::managed_instance_attestation::{
    ManagedInstanceAttestation, UpdateManagedInstanceAttestationRequest,
};
use crate::model::relation::{AsyncModelLoader, AsyncVecLoader};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait ManagedInstanceAttestationRepository: Send + Sync {
    async fn create_attestation(
        &self,
        request: ManagedInstanceAttestation,
    ) -> Result<ManagedInstanceAttestationId, DataLayerError>;

    async fn update_attestation(
        &self,
        id: &ManagedInstanceAttestationId,
        request: UpdateManagedInstanceAttestationRequest,
    ) -> Result<(), DataLayerError>;

    async fn get_attestation(
        &self,
        id: &ManagedInstanceAttestationId,
    ) -> Result<ManagedInstanceAttestation, DataLayerError>;

    async fn get_by_instance_id(
        &self,
        id: &ManagedInstanceId,
    ) -> Result<Vec<ManagedInstanceAttestation>, DataLayerError>;
}

#[async_trait::async_trait]
impl AsyncModelLoader<ManagedInstanceAttestation>
    for Arc<dyn ManagedInstanceAttestationRepository>
{
    async fn load(
        &self,
        id: &ManagedInstanceAttestationId,
    ) -> Result<ManagedInstanceAttestation, DataLayerError> {
        self.get_attestation(id).await
    }
}

pub struct ManagedInstanceAttestationsLoader {
    pub id: ManagedInstanceId,
    pub managed_instance_repository: Arc<dyn ManagedInstanceAttestationRepository>,
}

#[async_trait::async_trait]
impl AsyncVecLoader<ManagedInstanceAttestation> for ManagedInstanceAttestationsLoader {
    async fn load(&self) -> Result<Vec<ManagedInstanceAttestation>, DataLayerError> {
        self.managed_instance_repository
            .get_by_instance_id(&self.id)
            .await
    }
}
