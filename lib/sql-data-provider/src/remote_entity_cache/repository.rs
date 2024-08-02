use crate::entity::remote_entity_cache;
use crate::mapper::to_data_layer_error;
use crate::remote_entity_cache::RemoteEntityCacheProvider;
use async_trait::async_trait;
use one_core::model::remote_entity_cache::{
    CacheType, RemoteEntityCache, RemoteEntityCacheRelations,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::json_ld_context_repository::RemoteEntityCacheRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, ModelTrait, PaginatorTrait, QueryFilter,
    QueryOrder,
};
use shared_types::RemoteEntityCacheId;

#[async_trait]
impl RemoteEntityCacheRepository for RemoteEntityCacheProvider {
    async fn create(
        &self,
        request: RemoteEntityCache,
    ) -> Result<RemoteEntityCacheId, DataLayerError> {
        let context = remote_entity_cache::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(context.id)
    }

    async fn delete_oldest(&self, r#type: CacheType) -> Result<(), DataLayerError> {
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

    async fn get_by_id(
        &self,
        id: &RemoteEntityCacheId,
        _relations: &RemoteEntityCacheRelations,
    ) -> Result<Option<RemoteEntityCache>, DataLayerError> {
        let context = remote_entity_cache::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(context.map(|context| context.try_into()).transpose()?)
    }

    async fn get_by_key(&self, key: &str) -> Result<Option<RemoteEntityCache>, DataLayerError> {
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

    async fn update(&self, request: RemoteEntityCache) -> Result<(), DataLayerError> {
        remote_entity_cache::ActiveModel::from(request)
            .update(&self.db)
            .await
            .map_err(|e| match e {
                DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
                _ => DataLayerError::Db(e.into()),
            })?;
        Ok(())
    }
}
