use std::sync::Arc;

use anyhow::Context;
use time::OffsetDateTime;

use super::{CachingLoader, CachingLoaderError, ResolveResult, Resolver};
use crate::provider::http_client::{self, HttpClient};
use crate::provider::remote_entity_storage::{
    RemoteEntity, RemoteEntityStorage, RemoteEntityStorageError, RemoteEntityType,
};
use crate::service::ssi_issuer::dto::SdJwtVcTypeMetadataResponseDTO;

#[derive(Debug, thiserror::Error)]
pub enum VctTypeMetadataResolverError {
    #[error("Http client error: {0}")]
    HttpClient(#[from] http_client::Error),

    #[error("Failed deserializing response body: {0}")]
    InvalidResponseBody(#[from] serde_json::Error),

    #[error("Storage error: {0}")]
    Storage(#[from] RemoteEntityStorageError),

    #[error("Caching loader error: {0}")]
    CachingLoader(#[from] CachingLoaderError),
}

#[derive(Debug, thiserror::Error)]
pub enum VctCacheError {
    #[error(transparent)]
    Resolver(#[from] VctTypeMetadataResolverError),

    #[error("Failed deserializing value: {0}")]
    InvalidValue(#[from] serde_json::Error),
}

pub struct VctTypeMetadataCache {
    inner: CachingLoader<VctTypeMetadataResolverError>,
    resolver: Arc<dyn Resolver<Error = VctTypeMetadataResolverError> + Send>,
}

impl VctTypeMetadataCache {
    pub fn new(
        resolver: Arc<dyn Resolver<Error = VctTypeMetadataResolverError>>,
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
            let request = RemoteEntity {
                last_modified: OffsetDateTime::now_utc(),
                entity_type: self.inner.remote_entity_type,
                value: serde_json::to_vec(&vct).context("Serializing what we just deserialized")?,
                key: vct.vct,
                hit_counter: 0,
                media_type: None,
                persistent: true,
            };

            self.inner
                .storage
                .insert(request)
                .await
                .context("Failed inserting JSON schema")?;
        }

        Ok(())
    }

    pub async fn get(
        &self,
        vct: &str,
    ) -> Result<Option<SdJwtVcTypeMetadataResponseDTO>, VctCacheError> {
        // Only make HTTP requests for http and https schemes
        if let Ok(url) = url::Url::parse(vct) {
            if url.scheme() == "http" || url.scheme() == "https" {
                let (metadata, _) = self.inner.get(vct, self.resolver.clone(), false).await?;
                return Ok(Some(serde_json::from_slice(&metadata)?));
            }
        }

        // For all other cases (non-HTTP URLs or invalid URLs), just check the cache
        let metadata = self
            .inner
            .get_if_cached(vct)
            .await?
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()?;

        Ok(metadata)
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
    type Error = VctTypeMetadataResolverError;

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
        })
    }
}
