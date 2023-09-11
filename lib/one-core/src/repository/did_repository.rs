use crate::model::did::{Did, DidId, DidRelations, DidValue, GetDidList, GetDidQuery};
use crate::model::organisation::OrganisationId;

use super::error::DataLayerError;

#[async_trait::async_trait]
pub trait DidRepository {
    async fn create_did(&self, request: Did) -> Result<DidId, DataLayerError>;

    async fn get_did(&self, id: &DidId, relations: &DidRelations) -> Result<Did, DataLayerError>;

    async fn get_did_by_value(
        &self,
        value: &DidValue,
        relations: &DidRelations,
    ) -> Result<Did, DataLayerError>;

    async fn get_did_list(&self, query_params: GetDidQuery) -> Result<GetDidList, DataLayerError>;

    async fn get_local_dids(
        &self,
        organisation_id: &OrganisationId,
    ) -> Result<Vec<Did>, DataLayerError>;
}
