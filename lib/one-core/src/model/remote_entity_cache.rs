use one_dto_mapper::{From, Into};
use shared_types::RemoteEntityCacheEntryId;
use time::OffsetDateTime;

use crate::provider::remote_entity_storage::RemoteEntityType;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteEntityCacheEntry {
    pub id: RemoteEntityCacheEntryId,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    pub key: String,
    pub value: Vec<u8>,

    pub hit_counter: u32,

    pub r#type: CacheType,

    pub media_type: Option<String>,
    pub persistent: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, From, Into)]
#[from(RemoteEntityType)]
#[into(RemoteEntityType)]
pub enum CacheType {
    DidDocument,
    JsonLdContext,
    StatusListCredential,
    VctMetadata,
    JsonSchema,
    TrustList,
    X509Crl,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct RemoteEntityCacheRelations {}
