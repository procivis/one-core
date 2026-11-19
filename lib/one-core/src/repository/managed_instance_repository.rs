use std::sync::Arc;

use shared_types::ManagedInstanceId;

use super::error::DataLayerError;
use crate::model::managed_instance::{
    ManagedInstance, ManagedInstanceList, ManagedInstanceListQuery, UpdateManagedInstanceRequest,
};
use crate::model::relation::AsyncModelLoader;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait ManagedInstanceRepository: Send + Sync {
    async fn create(&self, request: ManagedInstance) -> Result<ManagedInstanceId, DataLayerError>;

    async fn get(&self, id: &ManagedInstanceId) -> Result<ManagedInstance, DataLayerError>;

    /// Locks the instance row until the end of the transaction and returns it as stored
    async fn lock(&self, id: &ManagedInstanceId) -> Result<ManagedInstance, DataLayerError>;

    async fn get_list(
        &self,
        query_params: ManagedInstanceListQuery,
    ) -> Result<ManagedInstanceList, DataLayerError>;

    async fn update(
        &self,
        id: &ManagedInstanceId,
        request: UpdateManagedInstanceRequest,
    ) -> Result<(), DataLayerError>;

    async fn delete(&self, id: &ManagedInstanceId) -> Result<(), DataLayerError>;
}

#[async_trait::async_trait]
impl AsyncModelLoader<ManagedInstance> for Arc<dyn ManagedInstanceRepository> {
    async fn load(&self, id: &ManagedInstanceId) -> Result<ManagedInstance, DataLayerError> {
        self.get(id).await
    }
}
