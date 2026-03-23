use shared_types::{OrganisationId, VerifierInstanceId};

use crate::model::verifier_instance::{VerifierInstance, VerifierInstanceRelations};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait VerifierInstanceRepository: Send + Sync {
    async fn create(&self, request: VerifierInstance)
    -> Result<VerifierInstanceId, DataLayerError>;

    async fn get(
        &self,
        id: &VerifierInstanceId,
        relations: &VerifierInstanceRelations,
    ) -> Result<Option<VerifierInstance>, DataLayerError>;

    async fn get_by_org_id(
        &self,
        organisation_id: &OrganisationId,
    ) -> Result<Option<VerifierInstance>, DataLayerError>;
}
