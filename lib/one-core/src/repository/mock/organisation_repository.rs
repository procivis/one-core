use crate::{
    model::organisation::{Organisation, OrganisationId, OrganisationRelations},
    repository::error::DataLayerError,
};
use mockall::*;

#[derive(Default)]
struct OrganisationRepository;

mock! {
    pub OrganisationRepository {
        pub fn create_organisation(
            &self,
            request: Organisation,
        ) -> Result<OrganisationId, DataLayerError>;

        pub fn get_organisation(
            &self,
            id: &OrganisationId,
            relations: &OrganisationRelations
        ) -> Result<Option<Organisation>, DataLayerError>;

        pub fn get_organisation_list(&self) -> Result<Vec<Organisation>, DataLayerError>;
    }
}

#[async_trait::async_trait]
impl crate::repository::organisation_repository::OrganisationRepository
    for MockOrganisationRepository
{
    async fn create_organisation(
        &self,
        request: Organisation,
    ) -> Result<OrganisationId, DataLayerError> {
        self.create_organisation(request)
    }

    async fn get_organisation(
        &self,
        id: &OrganisationId,
        relations: &OrganisationRelations,
    ) -> Result<Option<Organisation>, DataLayerError> {
        self.get_organisation(id, relations)
    }

    async fn get_organisation_list(&self) -> Result<Vec<Organisation>, DataLayerError> {
        self.get_organisation_list()
    }
}
