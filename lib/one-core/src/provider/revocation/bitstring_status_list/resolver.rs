use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::provider::caching_loader::{CachingLoader, ResolveResult, Resolver};
use crate::provider::http_client::HttpClient;
use crate::provider::revocation::error::RevocationError;

pub struct StatusListResolver {
    pub client: Arc<dyn HttpClient>,
}

pub type StatusListCachingLoader = CachingLoader<RevocationError>;

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct StatusListCacheEntry {
    pub content: Vec<u8>,
    pub content_type: Option<String>,
}

#[async_trait]
impl Resolver for StatusListResolver {
    type Error = RevocationError;

    async fn do_resolve(
        &self,
        url: &str,
        _previous: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let response = self.client.get(url).send().await?.error_for_status()?;
        let content_type = response
            .header_get("Content-Type")
            .ok_or_else(|| RevocationError::MappingError("Content-Type not present".to_string()))?
            .to_owned();
        let cache_entry = StatusListCacheEntry {
            content: response.body,
            // This is also put there for compatibility reason
            content_type: Some(content_type.clone()),
        };
        Ok(ResolveResult::NewValue {
            content: serde_json::to_vec(&cache_entry)?,
            media_type: Some(content_type),
        })
    }
}

impl StatusListResolver {
    pub fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }
}
