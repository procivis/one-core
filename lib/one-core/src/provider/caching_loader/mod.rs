//! Module for loading cached entities.
//!
//! # Caching
//!
//! Some entities are cached. This is helpful for mobile devices with intermittent
//! internet connectivity, as well as for system optimization with entities not
//! expected to change (i.e. JSON-LD contexts). See the [caching][cac]
//! docs for more information about cached entities.
//!
//! [cac]: https://docs.procivis.ch/api/caching

use std::cmp::min;
use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use super::remote_entity_storage::{
    RemoteEntity, RemoteEntityStorage, RemoteEntityStorageError, RemoteEntityType,
};
use crate::proto::http_client;

pub mod android_attestation_crl;
pub mod json_ld_context;
pub mod json_schema;
pub mod trust_list;
pub mod vct;
pub mod x509_crl;

#[async_trait]
pub trait Resolver: Send + Sync {
    type Error: From<RemoteEntityStorageError>;

    async fn do_resolve(
        &self,
        key: &str,
        last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error(transparent)]
    Resolver(#[from] ResolverError),

    #[error("Failed deserializing cached value: {0}")]
    InvalidCachedValue(#[from] InvalidCachedValueError),
}

#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    #[error("Http client error: {0}")]
    HttpClient(#[from] http_client::Error),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Failed deserializing response body: {0}")]
    InvalidResponseBody(#[from] serde_json::Error),

    #[error("Storage error: {0}")]
    Storage(#[from] RemoteEntityStorageError),

    #[error("Caching loader error: {0}")]
    CachingLoader(#[from] CachingLoaderError),
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub enum InvalidCachedValueError {
    SerdeJson(#[from] serde_json::Error),
    Hasher(#[from] one_crypto::HasherError),
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum CachingLoaderError {
    #[error("Unexpected resolve result")]
    UnexpectedResolveResult,
}

pub enum ResolveResult {
    NewValue {
        content: Vec<u8>,
        media_type: Option<String>,
        expiry_date: Option<OffsetDateTime>,
    },
    LastModificationDateUpdate(OffsetDateTime),
}

#[derive(Clone)]
pub struct CachingLoader<E = ResolverError> {
    pub remote_entity_type: RemoteEntityType,
    pub storage: Arc<dyn RemoteEntityStorage>,

    cache_size: usize,
    cache_refresh_timeout: time::Duration,
    refresh_after: time::Duration,

    clean_old_mutex: Arc<Mutex<()>>,

    _marker: std::marker::PhantomData<E>,
}

impl<E: From<CachingLoaderError> + From<RemoteEntityStorageError>> CachingLoader<E> {
    pub fn new(
        remote_entity_type: RemoteEntityType,
        storage: Arc<dyn RemoteEntityStorage>,
        cache_size: usize,
        cache_refresh_timeout: time::Duration,
        refresh_after: time::Duration,
    ) -> Self {
        Self {
            remote_entity_type,
            storage,
            cache_size,
            cache_refresh_timeout,
            refresh_after,
            clean_old_mutex: Arc::new(Mutex::new(())),
            _marker: std::marker::PhantomData,
        }
    }

    pub async fn get(
        &self,
        url: &str,
        resolver: Arc<dyn Resolver<Error = E>>,
        force_refresh: bool,
    ) -> Result<(Vec<u8>, Option<String>), E> {
        let cached_entry_opt = self.storage.get_by_key(url).await?;

        let result = {
            if let Some(cached_entry) = cached_entry_opt {
                let persistent = cached_entry.expiration_date.is_none();

                if force_refresh && !persistent {
                    self.new_cache_entry(url, &resolver).await
                } else {
                    self.resolve_with_caching(url, cached_entry, &resolver)
                        .await
                }
            } else {
                self.new_cache_entry(url, &resolver).await
            }
        }?;

        self.clean_old_entries_if_needed().await?;
        Ok(result)
    }

    pub async fn get_if_cached(&self, key: &str) -> Result<Option<Vec<u8>>, E> {
        let entity = self.storage.get_by_key(key).await?;

        Ok(entity.map(|v| v.value))
    }

    async fn resolve_with_caching(
        &self,
        url: &str,
        cached_entry: RemoteEntity,
        resolver: &Arc<dyn Resolver<Error = E>>,
    ) -> Result<(Vec<u8>, Option<String>), E> {
        let Some(expiration_date) = cached_entry.expiration_date else {
            // persistent value --> always up-to-date
            return Ok((cached_entry.value, cached_entry.media_type));
        };

        let requires_update = context_requires_update(
            cached_entry.last_modified,
            expiration_date,
            self.refresh_after,
        );

        let mut context = cached_entry;

        if requires_update != ContextRequiresUpdate::IsRecent {
            let result = resolver.do_resolve(url, Some(&context.last_modified)).await;

            match result {
                Ok(value) => match value {
                    ResolveResult::NewValue {
                        content,
                        media_type,
                        expiry_date,
                    } => {
                        context.last_modified = OffsetDateTime::now_utc();
                        context.value = content;
                        context.media_type = media_type;
                        context.expiration_date = self.effective_expiry(expiry_date)
                    }
                    ResolveResult::LastModificationDateUpdate(value) => {
                        context.last_modified = value;
                    }
                },
                Err(error) => {
                    if requires_update == ContextRequiresUpdate::MustBeUpdated {
                        return Err(error);
                    }
                }
            }
        }

        context.last_used = OffsetDateTime::now_utc();

        if let Err(error) = self.storage.insert(context.to_owned()).await {
            match error {
                RemoteEntityStorageError::NotUpdated => {
                    // ONE-4160: ignoring potential failure when update fails due to missing entry
                    // the updated entry might be deleted at this point by another thread
                    tracing::debug!(
                        "Cache entry deleted while updating. It will be recreated on next usage."
                    );
                }
                _ => return Err(error.into()),
            }
        }

        Ok((context.value, context.media_type))
    }

    async fn new_cache_entry(
        &self,
        url: &str,
        resolver: &Arc<dyn Resolver<Error = E>>,
    ) -> Result<(Vec<u8>, Option<String>), E> {
        match resolver.do_resolve(url, None).await? {
            ResolveResult::NewValue {
                content,
                media_type,
                expiry_date,
            } => {
                let now = OffsetDateTime::now_utc();
                self.storage
                    .insert(RemoteEntity {
                        last_modified: now,
                        expiration_date: self.effective_expiry(expiry_date),
                        entity_type: self.remote_entity_type,
                        key: url.to_string(),
                        value: content.to_owned(),
                        last_used: now,
                        media_type: media_type.clone(),
                    })
                    .await?;

                Ok((content, media_type))
            }
            ResolveResult::LastModificationDateUpdate(_) => {
                Err(CachingLoaderError::UnexpectedResolveResult.into())
            }
        }
    }

    /// Calculates the effective expiry date to use based on the value suggested by the resolver (if any)
    /// and the cache configuration.
    fn effective_expiry(&self, resolved_expiry: Option<OffsetDateTime>) -> Option<OffsetDateTime> {
        let default_exp = OffsetDateTime::now_utc() + self.cache_refresh_timeout;
        resolved_expiry
            .map(|exp| min(exp, default_exp))
            .or(Some(default_exp))
    }

    async fn clean_old_entries_if_needed(&self) -> Result<(), RemoteEntityStorageError> {
        let Ok(_lock) = self.clean_old_mutex.try_lock() else {
            // cleaning already happening in another thread
            return Ok(());
        };

        self.storage
            .delete_expired_or_least_used(self.remote_entity_type, self.cache_size)
            .await
    }
}

fn context_requires_update(
    last_modified: OffsetDateTime,
    expiration_date: OffsetDateTime,
    refresh_after: time::Duration,
) -> ContextRequiresUpdate {
    let now = OffsetDateTime::now_utc();

    if expiration_date < now {
        return ContextRequiresUpdate::MustBeUpdated;
    };

    let diff = now - last_modified;
    if diff <= refresh_after {
        ContextRequiresUpdate::IsRecent
    } else {
        ContextRequiresUpdate::CanBeUpdated
    }
}

#[derive(Debug, PartialEq)]
enum ContextRequiresUpdate {
    MustBeUpdated,
    CanBeUpdated,
    IsRecent,
}
