use shared_types::TrustAnchorId;

use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustRepository: Send + Sync {
    async fn create_trust_anchor(&self) -> Result<TrustAnchorId, DataLayerError>;
}
