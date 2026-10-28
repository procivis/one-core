use one_core::model::remote_entity_cache::RemoteEntityCacheEntry;
use one_core::repository::error::DataLayerError;
use sea_orm::Set;
use sha2::{Digest, Sha256};

use crate::entity::remote_entity_cache;

pub(crate) fn key_hash(key: &str) -> String {
    hex::encode(Sha256::digest(key))
}

impl From<RemoteEntityCacheEntry> for remote_entity_cache::ActiveModel {
    fn from(value: RemoteEntityCacheEntry) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            expiration_date: Set(value.expiration_date),
            key_hash: Set(key_hash(&value.key)),
            key: Set(value.key),
            value: Set(value.value),
            last_used: Set(value.last_used),
            r#type: Set(value.r#type.into()),
            media_type: Set(value.media_type),
        }
    }
}

impl TryFrom<remote_entity_cache::Model> for RemoteEntityCacheEntry {
    type Error = DataLayerError;

    fn try_from(value: remote_entity_cache::Model) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            expiration_date: value.expiration_date,
            key: value.key,
            value: value.value,
            last_used: value.last_used,
            r#type: value.r#type.into(),
            media_type: value.media_type,
        })
    }
}
