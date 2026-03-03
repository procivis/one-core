use shared_types::TrustListPublicationId;

use crate::model::trust_list_publication::{
    GetTrustListPublicationList, TrustListPublication, TrustListPublicationListQuery,
    TrustListPublicationRelations, UpdateTrustListPublicationRequest,
};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustListPublicationRepository: Send + Sync {
    async fn create(
        &self,
        entity: TrustListPublication,
    ) -> Result<TrustListPublicationId, DataLayerError>;

    async fn get(
        &self,
        id: TrustListPublicationId,
        relations: &TrustListPublicationRelations,
    ) -> Result<Option<TrustListPublication>, DataLayerError>;

    async fn list(
        &self,
        query: TrustListPublicationListQuery,
    ) -> Result<GetTrustListPublicationList, DataLayerError>;

    async fn update(
        &self,
        id: TrustListPublicationId,
        request: UpdateTrustListPublicationRequest,
    ) -> Result<(), DataLayerError>;

    async fn delete(&self, id: TrustListPublicationId) -> Result<(), DataLayerError>;
}
