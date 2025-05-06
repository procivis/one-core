use shared_types::{DidId, DidValue, OrganisationId};

use crate::model::did::{Did, DidListQuery, DidRelations, GetDidList, UpdateDidRequest};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait DidRepository: Send + Sync {
    async fn create_did(&self, request: Did) -> Result<DidId, DataLayerError>;

    async fn get_did(
        &self,
        id: &DidId,
        relations: &DidRelations,
    ) -> Result<Option<Did>, DataLayerError>;

    async fn get_did_by_value(
        &self,
        value: &DidValue,

        // None => try to find in all organisations
        // Some(None) => only give results with organisationId == NULL (remote trust entities)
        // Some(Some(id)) => only give results with organisationId == id
        organisation: Option<Option<OrganisationId>>,
        relations: &DidRelations,
    ) -> Result<Option<Did>, DataLayerError>;

    async fn get_did_list(&self, query: DidListQuery) -> Result<GetDidList, DataLayerError>;

    async fn update_did(&self, request: UpdateDidRequest) -> Result<(), DataLayerError>;
}
