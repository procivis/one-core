use crate::model::remote_entity_cache::CacheType;
use crate::service::cache::CacheService;
use crate::service::error::ServiceError;

impl CacheService {
    pub async fn prune_cache(&self, r#type: Option<Vec<CacheType>>) -> Result<(), ServiceError> {
        self.remote_entity_cache_repository
            .delete_all(r#type)
            .await
            .map_err(ServiceError::Repository)
    }
}
