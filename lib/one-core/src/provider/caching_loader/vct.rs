use std::sync::Arc;

use anyhow::Context;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use time::OffsetDateTime;

use super::{
    CacheError, CachingLoader, InvalidCachedValueError, ResolveResult, Resolver, ResolverError,
};
use crate::provider::http_client::HttpClient;
use crate::provider::remote_entity_storage::{RemoteEntity, RemoteEntityStorage, RemoteEntityType};
use crate::service::ssi_issuer::dto::SdJwtVcTypeMetadataResponseDTO;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait VctTypeMetadataFetcher: Send + Sync {
    async fn get(&self, vct: &str) -> Result<Option<SdJwtVcTypeMetadataCacheItem>, CacheError>;
}

pub struct VctTypeMetadataCache {
    inner: CachingLoader,
    resolver: Arc<dyn Resolver<Error = ResolverError> + Send>,
}

#[derive(Clone, Debug)]
pub struct SdJwtVcTypeMetadataCacheItem {
    pub metadata: SdJwtVcTypeMetadataResponseDTO,

    /// vct#integrity
    pub integrity: Option<String>,
}

impl VctTypeMetadataCache {
    pub fn new(
        resolver: Arc<dyn Resolver<Error = ResolverError> + Send>,
        storage: Arc<dyn RemoteEntityStorage>,
        cache_size: usize,
        cache_refresh_timeout: time::Duration,
        refresh_after: time::Duration,
    ) -> Self {
        Self {
            inner: CachingLoader::new(
                RemoteEntityType::VctMetadata,
                storage,
                cache_size,
                cache_refresh_timeout,
                refresh_after,
            ),
            resolver,
        }
    }

    // Fills the empty cache with values from `resource/sd_jwt_vc_vcts.json`
    pub async fn initialize_from_static_resources(&self) -> anyhow::Result<()> {
        let schemas = include_str!("../../../../../resource/sd_jwt_vc_vcts.json");

        let vcts: Vec<SdJwtVcTypeMetadataResponseDTO> =
            serde_json::from_str(schemas).context("Invalid VCT type metadata resource file")?;

        for vct in vcts {
            let now = OffsetDateTime::now_utc();
            let request = RemoteEntity {
                last_modified: now,
                entity_type: self.inner.remote_entity_type,
                value: serde_json::to_vec(&vct).context("Serializing what we just deserialized")?,
                key: vct.vct,
                last_used: now,
                media_type: None,
                expiration_date: None,
            };

            self.inner
                .storage
                .insert(request)
                .await
                .context("Failed inserting JSON schema")?;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl VctTypeMetadataFetcher for VctTypeMetadataCache {
    async fn get(&self, vct: &str) -> Result<Option<SdJwtVcTypeMetadataCacheItem>, CacheError> {
        // Only make HTTP requests for http and https schemes
        if let Ok(url) = url::Url::parse(vct)
            && (url.scheme() == "http" || url.scheme() == "https")
        {
            let (bytes, _) = self.inner.get(vct, self.resolver.clone(), false).await?;

            let hash_base64 = SHA256
                .hash_base64(&bytes)
                .map_err(Into::<InvalidCachedValueError>::into)?;

            return Ok(Some(SdJwtVcTypeMetadataCacheItem {
                metadata: serde_json::from_slice(&bytes)
                    .map_err(Into::<InvalidCachedValueError>::into)?,
                integrity: Some(format!("sha256-{hash_base64}")),
            }));
        }

        // For all other cases (non-HTTP URLs or invalid URLs), just check the cache
        let metadata: Option<SdJwtVcTypeMetadataResponseDTO> = self
            .inner
            .get_if_cached(vct)
            .await?
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()
            .map_err(Into::<InvalidCachedValueError>::into)?;

        Ok(metadata.map(|metadata| SdJwtVcTypeMetadataCacheItem {
            metadata,
            integrity: None,
        }))
    }
}

pub struct VctTypeMetadataResolver {
    client: Arc<dyn HttpClient>,
}

impl VctTypeMetadataResolver {
    pub fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Resolver for VctTypeMetadataResolver {
    type Error = ResolverError;

    async fn do_resolve(
        &self,
        key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let response = self.client.get(key).send().await?.error_for_status()?;

        serde_json::from_slice::<SdJwtVcTypeMetadataResponseDTO>(&response.body)?;

        Ok(ResolveResult::NewValue {
            content: response.body,
            media_type: None,
            expiry_date: None,
        })
    }
}
