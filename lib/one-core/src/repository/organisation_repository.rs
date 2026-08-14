use std::sync::Arc;

use shared_types::OrganisationId;

use super::error::DataLayerError;
use crate::model::organisation::{
    GetOrganisationList, Organisation, OrganisationListQuery, UpdateOrganisationRequest,
};
use crate::model::relation::AsyncModelLoader;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait OrganisationRepository: Send + Sync {
    async fn create_organisation(
        &self,
        request: Organisation,
    ) -> Result<OrganisationId, DataLayerError>;

    async fn update_organisation(
        &self,
        id: &OrganisationId,
        request: UpdateOrganisationRequest,
    ) -> Result<(), DataLayerError>;

    async fn get_organisation(&self, id: &OrganisationId) -> Result<Organisation, DataLayerError>;

    async fn get_organisation_for_wallet_provider(
        &self,
        wallet_provider: &str,
    ) -> Result<Option<Organisation>, DataLayerError>;

    async fn get_organisation_for_verifier_provider(
        &self,
        verifier_provider: &str,
    ) -> Result<Option<Organisation>, DataLayerError>;

    async fn get_organisation_list(
        &self,
        query: OrganisationListQuery,
    ) -> Result<GetOrganisationList, DataLayerError>;
}

#[async_trait::async_trait]
impl AsyncModelLoader<Organisation> for Arc<dyn OrganisationRepository> {
    async fn load(&self, id: &OrganisationId) -> Result<Organisation, DataLayerError> {
        self.get_organisation(id).await
    }
}
