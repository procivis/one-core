use async_trait::async_trait;
use one_core::model::remote_entity_cache::{
    CacheType, RemoteEntityCacheEntry, RemoteEntityCacheRelations,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait,
};
use shared_types::RemoteEntityCacheEntryId;
use time::OffsetDateTime;

use crate::entity::remote_entity_cache;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};
use crate::remote_entity_cache::RemoteEntityCacheProvider;

#[async_trait]
impl RemoteEntityCacheRepository for RemoteEntityCacheProvider {
    async fn create(
        &self,
        request: RemoteEntityCacheEntry,
    ) -> Result<RemoteEntityCacheEntryId, DataLayerError> {
        let context = remote_entity_cache::ActiveModel::from(request)
            .insert(&self.db.tx())
            .await
            .map_err(to_data_layer_error)?;

        Ok(context.id)
    }

    async fn delete_expired_or_least_used(
        &self,
        r#type: CacheType,
        target_max_size: u32,
    ) -> Result<(), DataLayerError> {
        let cache_type = remote_entity_cache::CacheType::from(r#type);

        // first delete all expired
        remote_entity_cache::Entity::delete_many()
            .filter(remote_entity_cache::Column::ExpirationDate.lt(OffsetDateTime::now_utc()))
            .filter(remote_entity_cache::Column::Type.eq(cache_type))
            .exec(&self.db.tx())
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let current_size = self.get_repository_size(r#type).await?;

        if current_size <= target_max_size {
            // no need to continue
            return Ok(());
        }

        // delete oldest non-persistent (unused) to fit into the `target_max_size` limit
        let still_to_remove = current_size - target_max_size;

        let to_remove: Vec<RemoteEntityCacheEntryId> = remote_entity_cache::Entity::find()
            .select_only()
            .column(remote_entity_cache::Column::Id)
            .filter(remote_entity_cache::Column::ExpirationDate.is_not_null())
            .filter(remote_entity_cache::Column::Type.eq(cache_type))
            .order_by_asc(remote_entity_cache::Column::LastUsed)
            .limit(still_to_remove as u64)
            .into_tuple()
            .all(&self.db.tx())
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        if !to_remove.is_empty() {
            remote_entity_cache::Entity::delete_many()
                .filter(remote_entity_cache::Column::Id.is_in(to_remove))
                .exec(&self.db.tx())
                .await
                .map_err(|e| DataLayerError::Db(e.into()))?;
        }

        Ok(())
    }

    async fn delete_all(&self, r#type: Option<Vec<CacheType>>) -> Result<(), DataLayerError> {
        remote_entity_cache::Entity::delete_many()
            .filter(remote_entity_cache::Column::ExpirationDate.is_not_null())
            .apply_if(r#type, |query, value| {
                query.filter(
                    remote_entity_cache::Column::Type
                        .is_in(value.into_iter().map(remote_entity_cache::CacheType::from)),
                )
            })
            .exec(&self.db.tx())
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;
        Ok(())
    }

    async fn get_by_id(
        &self,
        id: &RemoteEntityCacheEntryId,
        _relations: &RemoteEntityCacheRelations,
    ) -> Result<Option<RemoteEntityCacheEntry>, DataLayerError> {
        let context = remote_entity_cache::Entity::find_by_id(id)
            .one(&self.db.tx())
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(context.map(|context| context.try_into()).transpose()?)
    }

    async fn get_by_key(
        &self,
        key: &str,
    ) -> Result<Option<RemoteEntityCacheEntry>, DataLayerError> {
        let context = remote_entity_cache::Entity::find()
            .filter(remote_entity_cache::Column::Key.eq(key))
            .one(&self.db.tx())
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(context.map(|context| context.try_into()).transpose()?)
    }

    async fn get_repository_size(&self, r#type: CacheType) -> Result<u32, DataLayerError> {
        Ok(remote_entity_cache::Entity::find()
            .filter(
                remote_entity_cache::Column::Type.eq(remote_entity_cache::CacheType::from(r#type)),
            )
            .count(&self.db.tx())
            .await
            .map_err(|e| DataLayerError::Db(e.into()))? as u32)
    }

    async fn update(&self, request: RemoteEntityCacheEntry) -> Result<(), DataLayerError> {
        remote_entity_cache::ActiveModel::from(request)
            .update(&self.db.tx())
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }
}
