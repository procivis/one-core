use std::sync::Arc;

use async_trait::async_trait;
use time::OffsetDateTime;

use crate::provider::caching_loader::{CachingLoader, ResolveResult, Resolver};
use crate::provider::http_client::HttpClient;
use crate::provider::revocation::error::RevocationError;

pub struct StatusListResolver {
    pub client: Arc<dyn HttpClient>,
}

pub type StatusListCachingLoader = CachingLoader<RevocationError>;

#[async_trait]
impl Resolver for StatusListResolver {
    type Error = RevocationError;

    async fn do_resolve(
        &self,
        url: &str,
        _previous: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        Ok(ResolveResult::NewValue(
            self.client.get(url).send().await?.error_for_status()?.body,
        ))
    }
}

impl StatusListResolver {
    pub fn new(client: Arc<dyn HttpClient>) -> Self {
        Self { client }
    }
}
