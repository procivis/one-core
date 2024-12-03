use shared_types::{DidId, TrustAnchorId, TrustEntityId};

use crate::model::trust_entity::{TrustEntity, TrustEntityRelations, UpdateTrustEntityRequest};
use crate::repository::error::DataLayerError;
use crate::service::trust_entity::dto::{GetTrustEntitiesResponseDTO, ListTrustEntitiesQueryDTO};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustEntityRepository: Send + Sync {
    async fn create(&self, entity: TrustEntity) -> Result<TrustEntityId, DataLayerError>;

    async fn get_by_did_id(&self, did_id: DidId) -> Result<Option<TrustEntity>, DataLayerError>;

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

    async fn update(
        &self,
        id: TrustEntityId,
        request: UpdateTrustEntityRequest,
    ) -> Result<(), DataLayerError>;
}
