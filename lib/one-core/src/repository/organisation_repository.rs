use crate::model::organisation::{Organisation, OrganisationId, OrganisationRelations};

use super::error::DataLayerError;

#[async_trait::async_trait]
pub trait OrganisationRepository: Send + Sync {
    async fn create_organisation(
        &self,
        request: Organisation,
    ) -> Result<OrganisationId, DataLayerError>;

    async fn get_organisation(
        &self,
        id: &OrganisationId,
        relations: &OrganisationRelations,
    ) -> Result<Option<Organisation>, DataLayerError>;

    async fn get_organisation_list(&self) -> Result<Vec<Organisation>, DataLayerError>;
}
