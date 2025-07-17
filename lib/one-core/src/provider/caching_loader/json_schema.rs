use std::sync::Arc;

use anyhow::Context;
use time::OffsetDateTime;

use super::{
    CacheError, CachingLoader, InvalidCachedValueError, ResolveResult, Resolver, ResolverError,
};
use crate::provider::http_client::HttpClient;
use crate::provider::remote_entity_storage::{RemoteEntity, RemoteEntityStorage, RemoteEntityType};

pub struct JsonSchemaCache {
    inner: CachingLoader,
    resolver: Arc<dyn Resolver<Error = ResolverError>>,
}

impl JsonSchemaCache {
    pub fn new(
        resolver: Arc<dyn Resolver<Error = ResolverError>>,
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
            let now = OffsetDateTime::now_utc();
            let request = RemoteEntity {
                last_modified: now,
                entity_type: self.inner.remote_entity_type,
                key: schema.key.clone(),
                value: serde_json::to_vec(&schema).context("Failed to serialize schema")?,
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

        return Ok(());

        #[derive(serde::Serialize, serde::Deserialize)]
        struct JsonSchema {
            #[serde(rename = "$id")]
            key: String,
            #[serde(flatten)]
            schema: serde_json::Value,
        }
    }

    pub async fn get(&self, key: &str) -> Result<serde_json::Value, CacheError> {
        let (schema, _) = self.inner.get(key, self.resolver.clone(), false).await?;

        Ok(serde_json::from_slice(&schema).map_err(Into::<InvalidCachedValueError>::into)?)
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
    type Error = ResolverError;

    async fn do_resolve(
        &self,
        key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let response = self.client.get(key).send().await?.error_for_status()?;

        Ok(ResolveResult::NewValue {
            content: response.body,
            media_type: None,
            expiry_date: None,
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
