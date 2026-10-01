use async_trait::async_trait;
use autometrics::autometrics;
use futures::FutureExt;
use one_core::model::remote_entity_cache::{CacheType, RemoteEntityCacheEntry};
use one_core::proto::transaction_manager::IsolationLevel;
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait,
};
use shared_types::RemoteEntityCacheEntryId;

use crate::entity::remote_entity_cache;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};
use crate::remote_entity_cache::RemoteEntityCacheProvider;

#[autometrics]
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

    async fn delete_expired_or_least_used(
        &self,
        r#type: CacheType,
        target_max_size: u32,
    ) -> Result<(), DataLayerError> {
        let cache_type = remote_entity_cache::CacheType::from(r#type);

        // Multiple instances cleaning the same cache type concurrently deadlock on overlapping ranges.
        // READ COMMITTED disables the gap locks. Same pattern as ONE-7015.
        self.db
            .tx_with_config(
                async {
                    // first delete all expired
                    remote_entity_cache::Entity::delete_many()
                        .filter(
                            remote_entity_cache::Column::ExpirationDate
                                .lt(one_core::clock::now_utc()),
                        )
                        .filter(remote_entity_cache::Column::Type.eq(cache_type))
                        .exec(&self.db)
                        .await
                        .map_err(|e| DataLayerError::Db(e.into()))?;

                    let current_size = self.get_repository_size(r#type).await?;

                    if current_size <= target_max_size {
                        // no need to continue
                        return Ok::<_, DataLayerError>(());
                    }

                    // delete oldest non-persistent (unused) to fit into the `target_max_size` limit
                    let still_to_remove = current_size - target_max_size;

                    let to_remove: Vec<RemoteEntityCacheEntryId> =
                        remote_entity_cache::Entity::find()
                            .select_only()
                            .column(remote_entity_cache::Column::Id)
                            .filter(remote_entity_cache::Column::ExpirationDate.is_not_null())
                            .filter(remote_entity_cache::Column::Type.eq(cache_type))
                            .order_by_asc(remote_entity_cache::Column::LastUsed)
                            .limit(still_to_remove as u64)
                            .into_tuple()
                            .all(&self.db)
                            .await
                            .map_err(|e| DataLayerError::Db(e.into()))?;

                    if !to_remove.is_empty() {
                        remote_entity_cache::Entity::delete_many()
                            .filter(remote_entity_cache::Column::Id.is_in(to_remove))
                            .exec(&self.db)
                            .await
                            .map_err(|e| DataLayerError::Db(e.into()))?;
                    }

                    Ok(())
                }
                .boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await??;

        Ok(())
    }

    async fn delete_all(&self, r#type: Option<Vec<CacheType>>) -> Result<(), DataLayerError> {
        self.db
            .tx_with_config(
                async {
                    remote_entity_cache::Entity::delete_many()
                        .filter(remote_entity_cache::Column::ExpirationDate.is_not_null())
                        .apply_if(r#type, |query, value| {
                            query.filter(
                                remote_entity_cache::Column::Type.is_in(
                                    value.into_iter().map(remote_entity_cache::CacheType::from),
                                ),
                            )
                        })
                        .exec(&self.db)
                        .await
                        .map_err(|e| DataLayerError::Db(e.into()))?;
                    Ok::<_, DataLayerError>(())
                }
                .boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await??;
        Ok(())
    }

    async fn get_by_id(
        &self,
        id: &RemoteEntityCacheEntryId,
    ) -> Result<RemoteEntityCacheEntry, DataLayerError> {
        let context = remote_entity_cache::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::RemoteEntityCache,
                id: (*id).into(),
            })?;

        context.try_into()
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

        context.map(|context| context.try_into()).transpose()
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
