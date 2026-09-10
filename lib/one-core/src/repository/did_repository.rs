use std::sync::Arc;

use shared_types::{DidId, DidValue, OrganisationId};

use crate::model::did::{Did, DidListQuery, GetDidList, UpdateDidRequest};
use crate::model::relation::AsyncModelLoader;
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait DidRepository: Send + Sync {
    async fn create_did(&self, request: Did) -> Result<DidId, DataLayerError>;

    async fn get_did(&self, id: &DidId) -> Result<Did, DataLayerError>;

    async fn get_did_by_value(
        &self,
        value: &DidValue,

        // None => try to find in all organisations
        // Some(None) => only give results with organisationId == NULL (remote trust entities)
        // Some(Some(id)) => only give results with organisationId == id
        organisation: Option<Option<OrganisationId>>,
    ) -> Result<Option<Did>, DataLayerError>;

    async fn get_did_list(&self, query: DidListQuery) -> Result<GetDidList, DataLayerError>;

    async fn update_did(&self, id: &DidId, request: UpdateDidRequest)
    -> Result<(), DataLayerError>;

    async fn delete_did(&self, did: &Did) -> Result<(), DataLayerError>;

    /// Deletes the DID and its `key_did` rows
    async fn hard_delete(&self, id: &DidId) -> Result<(), DataLayerError>;
}

#[async_trait::async_trait]
impl AsyncModelLoader<Did> for Arc<dyn DidRepository> {
    async fn load(&self, id: &DidId) -> Result<Did, DataLayerError> {
        self.get_did(id).await
    }
}
