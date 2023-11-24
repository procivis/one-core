use shared_types::{DidId, DidValue};

use super::error::DataLayerError;
use crate::model::did::{Did, DidListQuery, DidRelations, GetDidList, UpdateDidRequest};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait DidRepository {
    async fn create_did(&self, request: Did) -> Result<DidId, DataLayerError>;

    async fn get_did(&self, id: &DidId, relations: &DidRelations) -> Result<Did, DataLayerError>;

    async fn get_did_by_value(
        &self,
        value: &DidValue,
        relations: &DidRelations,
    ) -> Result<Did, DataLayerError>;

    async fn get_did_list(&self, query: DidListQuery) -> Result<GetDidList, DataLayerError>;

    async fn update_did(&self, request: UpdateDidRequest) -> Result<(), DataLayerError>;
}
