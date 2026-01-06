use strum::IntoEnumIterator;

use crate::model::remote_entity_cache::CacheType;
use crate::service::cache::CacheService;
use crate::service::error::ServiceError;

impl CacheService {
    pub async fn prune_cache(&self, r#type: Option<Vec<CacheType>>) -> Result<(), ServiceError> {
        let types = r#type.clone().unwrap_or(CacheType::iter().collect());
        self.remote_entity_cache_repository
            .delete_all(r#type)
            .await
            .map_err(ServiceError::Repository)?;

        tracing::info!("Deleted cache entries of type(s): {:?}", types);

        Ok(())
    }
}
