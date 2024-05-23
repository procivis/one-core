use shared_types::TrustAnchorId;

use crate::model::trust_anchor::TrustAnchor;
use crate::repository::error::DataLayerError;
use crate::service::trust_anchor::dto::{GetTrustAnchorsResponseDTO, ListTrustAnchorsQueryDTO};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustAnchorRepository: Send + Sync {
    async fn create(&self, anchor: TrustAnchor) -> Result<TrustAnchorId, DataLayerError>;
    async fn get(&self, id: TrustAnchorId) -> Result<Option<TrustAnchor>, DataLayerError>;
    async fn list(
        &self,
        filters: ListTrustAnchorsQueryDTO,
    ) -> Result<GetTrustAnchorsResponseDTO, DataLayerError>;
}
