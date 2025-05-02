use async_trait::async_trait;
use shared_types::{DidId, IdentifierId};

use crate::model::identifier::{Identifier, IdentifierRelations, UpdateIdentifierRequest};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait IdentifierRepository: Send + Sync {
    async fn create(&self, request: Identifier) -> Result<IdentifierId, DataLayerError>;
    async fn get_from_did_id(
        &self,
        did_id: DidId,
        relations: &IdentifierRelations,
    ) -> Result<Option<Identifier>, DataLayerError>;
    async fn update(
        &self,
        id: &IdentifierId,
        request: UpdateIdentifierRequest,
    ) -> Result<(), DataLayerError>;
    async fn delete(&self, id: &IdentifierId) -> Result<(), DataLayerError>;
}
