use async_trait::async_trait;
use shared_types::IdentifierId;

use crate::model::identifier::Identifier;
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait IdentifierRepository: Send + Sync {
    async fn create(&self, request: Identifier) -> Result<IdentifierId, DataLayerError>;
    async fn delete(&self, id: &IdentifierId) -> Result<(), DataLayerError>;
}
