use crate::service::trust_entity::dto::{GetTrustEntitiesResponseDTO, ListTrustEntitiesQueryDTO};
use crate::{
    model::trust_entity::{TrustEntity, TrustEntityRelations},
    repository::error::DataLayerError,
};
use shared_types::{TrustAnchorId, TrustEntityId};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustEntityRepository: Send + Sync {
    async fn create(&self, entity: TrustEntity) -> Result<TrustEntityId, DataLayerError>;

    async fn get_by_trust_anchor_id(
        &self,
        trust_anchor_id: TrustAnchorId,
    ) -> Result<Vec<TrustEntity>, DataLayerError>;

    async fn delete(&self, id: TrustEntityId) -> Result<(), DataLayerError>;

    async fn get(
        &self,
        id: TrustEntityId,
        relations: &TrustEntityRelations,
    ) -> Result<Option<TrustEntity>, DataLayerError>;

    async fn list(
        &self,
        filters: ListTrustEntitiesQueryDTO,
    ) -> Result<GetTrustEntitiesResponseDTO, DataLayerError>;
}
