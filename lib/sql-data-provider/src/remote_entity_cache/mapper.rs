use one_core::model::remote_entity_cache::RemoteEntityCache;
use one_core::repository::error::DataLayerError;
use sea_orm::Set;

use crate::entity::remote_entity_cache;

impl From<RemoteEntityCache> for remote_entity_cache::ActiveModel {
    fn from(value: RemoteEntityCache) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            key: Set(value.key),
            value: Set(value.value),
            hit_counter: Set(value.hit_counter),
            r#type: Set(value.r#type.into()),
            media_type: Set(value.media_type),
        }
    }
}

impl TryFrom<remote_entity_cache::Model> for RemoteEntityCache {
    type Error = DataLayerError;

    fn try_from(value: remote_entity_cache::Model) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            value: value.value,
            hit_counter: value.hit_counter,
            r#type: value.r#type.into(),
            media_type: value.media_type,
        })
    }
}
