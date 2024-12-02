use std::sync::Arc;

use time::OffsetDateTime;

use super::{CachingLoader, CachingLoaderError, ResolveResult, Resolver};
use crate::provider::http_client::{self, HttpClient};
use crate::provider::remote_entity_storage::{
    RemoteEntity, RemoteEntityStorage, RemoteEntityStorageError, RemoteEntityType,
};

#[derive(Debug, thiserror::Error)]
pub enum JsonSchemaResolverError {
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
pub enum JsonSchemaCacheError {
    #[error(transparent)]
    Resolver(#[from] JsonSchemaResolverError),

    #[error("Failed deserializing cached value: {0}")]
    InvalidCachedValue(#[from] serde_json::Error),
}

pub struct JsonSchemaCache {
    inner: CachingLoader<JsonSchemaResolverError>,
    resolver: Arc<dyn Resolver<Error = JsonSchemaResolverError>>,
}

impl JsonSchemaCache {
    pub fn new(
        resolver: Arc<dyn Resolver<Error = JsonSchemaResolverError>>,
        storage: Arc<dyn RemoteEntityStorage>,
        cache_size: usize,
        cache_refresh_timeout: time::Duration,
        refresh_after: time::Duration,
    ) -> Self {
        Self {
            inner: CachingLoader::new(
                RemoteEntityType::JsonSchema,
                storage,
                cache_size,
                cache_refresh_timeout,
                refresh_after,
            ),
            resolver,
        }
    }

    // Fills the empty cache with values from `resource/sd_jwt_vc_schemas.json`
    // Panics if file contains invalid data
    pub async fn initialize_from_static_resources(&self) {
        let schemas = include_str!("../../../../../resource/sd_jwt_vc_schemas.json");

        #[derive(serde::Deserialize)]
        struct JsonSchema {
            key: String,
            schema: serde_json::Value,
        }

        let schemas: Vec<JsonSchema> =
            serde_json::from_str(schemas).expect("Invalid JSON schema resource file");

        for schema in schemas {
            let request = RemoteEntity {
                last_modified: OffsetDateTime::now_utc(),
                entity_type: self.inner.remote_entity_type,
                key: schema.key,
                value: serde_json::to_vec(&schema.schema).unwrap(),
                hit_counter: 0,
                media_type: None,
                persistent: true,
            };

            self.inner
                .storage
                .insert(request)
                .await
                .expect("Failed inserting JSON schema");
        }
    }

    pub async fn get(&self, key: &str) -> Result<serde_json::Value, JsonSchemaCacheError> {
        let (schema, _) = self.inner.get(key, self.resolver.clone()).await?;

        Ok(serde_json::from_slice(&schema)?)
    }
}

pub struct JsonSchemaResolver {
    client: Arc<dyn HttpClient>,
}

impl JsonSchemaResolver {
    pub fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Resolver for JsonSchemaResolver {
    type Error = JsonSchemaResolverError;

    async fn do_resolve(
        &self,
        key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let response = self.client.get(key).send().await?.error_for_status()?;

        let _: serde_json::Value = serde_json::from_slice(&response.body)?;

        Ok(ResolveResult::NewValue {
            content: response.body,
            media_type: None,
        })
    }
}
