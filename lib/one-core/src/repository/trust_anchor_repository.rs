use crate::{model::trust_anchor::TrustAnchor, repository::error::DataLayerError};
use shared_types::TrustAnchorId;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustAnchorRepository: Send + Sync {
    async fn create(&self, anchor: TrustAnchor) -> Result<TrustAnchorId, DataLayerError>;
    async fn get(&self, id: TrustAnchorId) -> Result<Option<TrustAnchor>, DataLayerError>;
}
