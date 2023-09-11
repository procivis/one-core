use crate::model::organisation::OrganisationId;
use crate::{
    model::did::{Did, DidId, DidRelations, DidValue, GetDidList, GetDidQuery},
    repository::error::DataLayerError,
};
use mockall::*;

#[derive(Default)]
struct DidRepository;

mock! {
    pub DidRepository {
        pub fn create_did(&self, request: Did) -> Result<DidId, DataLayerError>;

        pub fn get_did(&self, id: &DidId, relations: &DidRelations) -> Result<Did, DataLayerError>;

        pub fn get_did_by_value(
            &self,
            value: &DidValue,
            relations: &DidRelations,
        ) -> Result<Did, DataLayerError>;

        pub fn get_did_list(&self, query_params: GetDidQuery) -> Result<GetDidList, DataLayerError>;

        pub fn get_local_dids(
            &self,
            organisation_id: &OrganisationId,
        ) -> Result<Vec<Did>, DataLayerError>;
    }
}

#[async_trait::async_trait]
impl crate::repository::did_repository::DidRepository for MockDidRepository {
    async fn create_did(&self, request: Did) -> Result<DidId, DataLayerError> {
        self.create_did(request)
    }

    async fn get_did(&self, id: &DidId, relations: &DidRelations) -> Result<Did, DataLayerError> {
        self.get_did(id, relations)
    }

    async fn get_did_by_value(
        &self,
        value: &DidValue,
        relations: &DidRelations,
    ) -> Result<Did, DataLayerError> {
        self.get_did_by_value(value, relations)
    }

    async fn get_did_list(&self, query_params: GetDidQuery) -> Result<GetDidList, DataLayerError> {
        self.get_did_list(query_params)
    }

    async fn get_local_dids(
        &self,
        organisation_id: &OrganisationId,
    ) -> Result<Vec<Did>, DataLayerError> {
        self.get_local_dids(organisation_id)
    }
}
