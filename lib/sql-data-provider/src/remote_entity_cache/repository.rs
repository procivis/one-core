use async_trait::async_trait;
use one_core::model::remote_entity_cache::{
    CacheType, RemoteEntityCacheEntry, RemoteEntityCacheRelations,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QueryTrait,
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
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(context.id)
    }

    async fn delete_expired_or_least_used(&self, r#type: CacheType) -> Result<(), DataLayerError> {
        let delete_result = remote_entity_cache::Entity::delete_many()
            .filter(remote_entity_cache::Column::ExpirationDate.lt(OffsetDateTime::now_utc()))
            .filter(
                remote_entity_cache::Column::Type
                    .eq(remote_entity_cache::CacheType::from(r#type.clone())),
            )
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        // Don't bother looking at usage if expired entries have been removed
        if delete_result.rows_affected > 0 {
            return Ok(());
        }

        if let Some(model) = remote_entity_cache::Entity::find()
            .order_by_asc(remote_entity_cache::Column::HitCounter)
            .order_by_asc(remote_entity_cache::Column::LastModified)
            .filter(
                remote_entity_cache::Column::Type.eq(remote_entity_cache::CacheType::from(r#type)),
            )
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?
        {
            model
                .delete(&self.db)
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
            .exec(&self.db)
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
            .one(&self.db)
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
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(context.map(|context| context.try_into()).transpose()?)
    }

    async fn get_repository_size(&self, r#type: CacheType) -> Result<u32, DataLayerError> {
        Ok(remote_entity_cache::Entity::find()
            .filter(
                remote_entity_cache::Column::Type.eq(remote_entity_cache::CacheType::from(r#type)),
            )
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))? as u32)
    }

    async fn update(&self, request: RemoteEntityCacheEntry) -> Result<(), DataLayerError> {
        remote_entity_cache::ActiveModel::from(request)
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }
}
