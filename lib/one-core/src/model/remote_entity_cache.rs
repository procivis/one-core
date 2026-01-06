use one_dto_mapper::{From, Into};
use shared_types::RemoteEntityCacheEntryId;
use strum::EnumIter;
use time::OffsetDateTime;

use crate::provider::remote_entity_storage::RemoteEntityType;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteEntityCacheEntry {
    pub id: RemoteEntityCacheEntryId,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub last_used: OffsetDateTime,
    pub expiration_date: Option<OffsetDateTime>,

    pub key: String,
    pub value: Vec<u8>,

    pub r#type: CacheType,
    pub media_type: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, From, Into, EnumIter)]
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
    AndroidAttestationCrl,
    OpenIDMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct RemoteEntityCacheRelations {}
