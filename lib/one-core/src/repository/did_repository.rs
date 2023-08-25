use crate::model::did::{Did, DidId, DidValue, GetDidList, GetDidQuery};

use super::error::DataLayerError;

#[async_trait::async_trait]
pub trait DidRepository {
    async fn create_did(&self, request: Did) -> Result<DidId, DataLayerError>;

    async fn get_did(&self, id: &DidId) -> Result<Did, DataLayerError>;

    async fn get_did_by_value(&self, value: &DidValue) -> Result<Did, DataLayerError>;

    async fn get_did_list(&self, query_params: GetDidQuery) -> Result<GetDidList, DataLayerError>;
}
