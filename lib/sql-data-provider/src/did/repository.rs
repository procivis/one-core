use super::DidProvider;
use one_core::{
    model::did::{Did, DidId, DidRelations, DidValue, GetDidList, GetDidQuery},
    repository::{did_repository::DidRepository, error::DataLayerError},
};

#[async_trait::async_trait]
impl DidRepository for DidProvider {
    async fn get_did(&self, id: &DidId, relations: &DidRelations) -> Result<Did, DataLayerError> {
        self.get_did_impl(id, relations).await
    }

    async fn get_did_by_value(
        &self,
        value: &DidValue,
        relations: &DidRelations,
    ) -> Result<Did, DataLayerError> {
        self.get_did_by_value_impl(value, relations).await
    }

    async fn get_did_list(&self, query_params: GetDidQuery) -> Result<GetDidList, DataLayerError> {
        self.get_did_list_impl(query_params).await
    }

    async fn create_did(&self, request: Did) -> Result<DidId, DataLayerError> {
        self.create_did_impl(request).await
    }
}
