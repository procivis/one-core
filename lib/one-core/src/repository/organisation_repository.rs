use shared_types::OrganisationId;

use super::error::DataLayerError;
use crate::model::organisation::{Organisation, OrganisationRelations, UpdateOrganisationRequest};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait OrganisationRepository: Send + Sync {
    async fn create_organisation(
        &self,
        request: Organisation,
    ) -> Result<OrganisationId, DataLayerError>;

    async fn update_organisation(
        &self,
        request: UpdateOrganisationRequest,
    ) -> Result<(), DataLayerError>;

    async fn get_organisation(
        &self,
        id: &OrganisationId,
        relations: &OrganisationRelations,
    ) -> Result<Option<Organisation>, DataLayerError>;

    async fn get_organisation_for_wallet_provider(
        &self,
        wallet_provider: &str,
    ) -> Result<Option<Organisation>, DataLayerError>;

    async fn get_organisation_list(&self) -> Result<Vec<Organisation>, DataLayerError>;
}
