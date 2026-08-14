use std::sync::Arc;

use shared_types::TrustCollectionId;

use crate::model::relation::AsyncModelLoader;
use crate::model::trust_collection::{
    GetTrustCollectionList, TrustCollection, TrustCollectionListQuery,
};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustCollectionRepository: Send + Sync {
    async fn create(&self, entity: TrustCollection) -> Result<TrustCollectionId, DataLayerError>;

    async fn get(&self, id: &TrustCollectionId) -> Result<TrustCollection, DataLayerError>;

    async fn list(
        &self,
        query: TrustCollectionListQuery,
    ) -> Result<GetTrustCollectionList, DataLayerError>;

    async fn delete(&self, id: TrustCollectionId) -> Result<(), DataLayerError>;
}

#[async_trait::async_trait]
impl AsyncModelLoader<TrustCollection> for Arc<dyn TrustCollectionRepository> {
    async fn load(&self, id: &TrustCollectionId) -> Result<TrustCollection, DataLayerError> {
        self.get(id).await
    }
}
