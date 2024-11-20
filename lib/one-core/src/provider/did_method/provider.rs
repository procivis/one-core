//! DID method provider.

use std::collections::HashMap;
use std::sync::Arc;

use shared_types::DidValue;

use super::dto::DidDocumentDTO;
use super::resolver::{DidCachingLoader, DidResolver};
use crate::provider::did_method::error::DidMethodProviderError;
use crate::provider::did_method::model::DidDocument;
use crate::provider::did_method::DidMethod;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait DidMethodProvider: Send + Sync {
    fn get_did_method(&self, did_method_id: &str) -> Option<Arc<dyn DidMethod>>;

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodProviderError>;
}

pub struct DidMethodProviderImpl {
    caching_loader: DidCachingLoader,
    did_methods: HashMap<String, Arc<dyn DidMethod>>,
    resolver: Arc<DidResolver>,
}

impl DidMethodProviderImpl {
    pub fn new(
        caching_loader: DidCachingLoader,
        did_methods: HashMap<String, Arc<dyn DidMethod>>,
        url_did_resolver: Option<Arc<dyn DidMethod>>,
    ) -> Self {
        let resolver = DidResolver {
            did_methods: did_methods.clone(),
            url_did_resolver,
        };

        Self {
            caching_loader,
            did_methods,
            resolver: Arc::new(resolver),
        }
    }
}

#[async_trait::async_trait]
impl DidMethodProvider for DidMethodProviderImpl {
    fn get_did_method(&self, did_method_id: &str) -> Option<Arc<dyn DidMethod>> {
        self.did_methods.get(did_method_id).cloned()
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodProviderError> {
        let (content, _media_type) = self
            .caching_loader
            .get(did.as_str(), self.resolver.clone())
            .await?;
        let dto: DidDocumentDTO = serde_json::from_slice(&content)?;
        Ok(dto.into())
    }
}
