use dto_mapper::{From, Into};
use shared_types::RemoteEntityCacheId;
use time::OffsetDateTime;

use crate::provider::remote_entity_storage::RemoteEntityType;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteEntityCache {
    pub id: RemoteEntityCacheId,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    pub key: String,
    pub value: Vec<u8>,

    pub hit_counter: u32,

    pub r#type: CacheType,
}

#[derive(Clone, Debug, Eq, PartialEq, From, Into)]
#[from(RemoteEntityType)]
#[into(RemoteEntityType)]
pub enum CacheType {
    DidDocument,
    JsonLdContext,
    StatusListCredential,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct RemoteEntityCacheRelations {}
