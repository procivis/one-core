//! Storage provider for caching.
//!
//! In-memory storage is supported natively; this can be extended with another storage
//! provider.
//!
//! # Caching
//!
//! Some entities are cached. This is helpful for mobile devices with intermittent
//! internet connectivity, as well as for system optimization with entities not
//! expected to change (i.e. JSON-LD contexts). See the [caching][cac]
//! docs for more information about cached entities.
//!
//! [cac]: https://docs.procivis.ch/api/caching

use one_dto_mapper::From;
use thiserror::Error;
use time::OffsetDateTime;

use crate::model::remote_entity_cache::RemoteEntityCacheEntry;

pub mod db_storage;
pub mod in_memory;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait RemoteEntityStorage: Send + Sync {
    async fn delete_expired_or_least_used(
        &self,
        entity_type: RemoteEntityType,
        target_max_size: usize,
    ) -> Result<(), RemoteEntityStorageError>;

    async fn get_by_key(&self, key: &str)
    -> Result<Option<RemoteEntity>, RemoteEntityStorageError>;

    async fn get_storage_size(
        &self,
        entity_type: RemoteEntityType,
    ) -> Result<usize, RemoteEntityStorageError>;

    async fn insert(&self, request: RemoteEntity) -> Result<(), RemoteEntityStorageError>;
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(RemoteEntityCacheEntry)]
pub struct RemoteEntity {
    pub last_modified: OffsetDateTime,

    /// `None` means the entry is persistent
    pub expiration_date: Option<OffsetDateTime>,

    #[from(rename = "r#type")]
    pub entity_type: RemoteEntityType,
    pub key: String,
    pub value: Vec<u8>,

    pub last_used: OffsetDateTime,

    pub media_type: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteEntityType {
    DidDocument,
    JsonLdContext,
    StatusListCredential,
    VctMetadata,
    JsonSchema,
    TrustList,
    X509Crl,
}

#[derive(Clone, Error, Debug)]
pub enum RemoteEntityStorageError {
    #[error("Delete error: `{0}`")]
    Delete(String),
    #[error("Get by key error: `{0}`")]
    GetByKey(String),
    #[error("Get storage size: `{0}`")]
    GetStorageSize(String),
    #[error("Insert: `{0}`")]
    Insert(String),
    #[error("Not updated")]
    NotUpdated,
}
