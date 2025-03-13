use std::sync::Arc;

use anyhow::Context;
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
    pub async fn initialize_from_static_resources(&self) -> anyhow::Result<()> {
        let schemas = include_str!("../../../../../resource/sd_jwt_vc_schemas.json");

        let schemas: Vec<JsonSchema> =
            serde_json::from_str(schemas).context("Invalid JSON schema resource file")?;

        for schema in schemas {
            let request = RemoteEntity {
                last_modified: OffsetDateTime::now_utc(),
                entity_type: self.inner.remote_entity_type,
                key: schema.key.clone(),
                value: serde_json::to_vec(&schema).context("Failed to serialize schema")?,
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

        return Ok(());

        #[derive(serde::Serialize, serde::Deserialize)]
        struct JsonSchema {
            #[serde(rename = "$id")]
            key: String,
            #[serde(flatten)]
            schema: serde_json::Value,
        }
    }

    pub async fn get(&self, key: &str) -> Result<serde_json::Value, JsonSchemaCacheError> {
        let (schema, _) = self.inner.get(key, self.resolver.clone(), false).await?;

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

        Ok(ResolveResult::NewValue {
            content: response.body,
            media_type: None,
        })
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_validate_static_json_schemas() {
        let schemas = include_str!("../../../../../resource/sd_jwt_vc_schemas.json");

        let schemas: Vec<serde_json::Value> = serde_json::from_str(schemas).unwrap();

        for schema in schemas {
            jsonschema::draft202012::new(&schema).unwrap();
        }
    }
}
