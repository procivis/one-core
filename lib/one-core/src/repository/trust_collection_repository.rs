use shared_types::TrustCollectionId;

use crate::model::trust_collection::{
    GetTrustCollectionList, TrustCollection, TrustCollectionListQuery, TrustCollectionRelations,
};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustCollectionRepository: Send + Sync {
    async fn create(&self, entity: TrustCollection) -> Result<TrustCollectionId, DataLayerError>;

    async fn get(
        &self,
        id: &TrustCollectionId,
        relations: &TrustCollectionRelations,
    ) -> Result<Option<TrustCollection>, DataLayerError>;

    async fn list(
        &self,
        query: TrustCollectionListQuery,
    ) -> Result<GetTrustCollectionList, DataLayerError>;

    async fn delete(&self, id: TrustCollectionId) -> Result<(), DataLayerError>;
}
