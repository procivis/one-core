//! DID method provider.

use std::sync::Arc;

use indexmap::IndexMap;
use shared_types::DidValue;

use super::dto::DidDocumentDTO;
use super::resolver::{DidCachingLoader, DidResolver};
use crate::provider::did_method::DidMethod;
use crate::provider::did_method::error::DidMethodProviderError;
use crate::provider::did_method::model::DidDocument;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait DidMethodProvider: Send + Sync {
    fn get_did_method(&self, did_method_id: &str) -> Option<Arc<dyn DidMethod>>;

    fn get_did_method_id(&self, did: &DidValue) -> Option<String>;

    fn get_did_method_by_method_name(
        &self,
        method_name: &str,
    ) -> Option<(String, Arc<dyn DidMethod>)>;

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodProviderError>;

    fn supported_method_names(&self) -> Vec<String>;
}

pub struct DidMethodProviderImpl {
    caching_loader: DidCachingLoader,
    did_methods: IndexMap<String, Arc<dyn DidMethod>>,
    resolver: Arc<DidResolver>,
}

impl DidMethodProviderImpl {
    pub fn new(
        caching_loader: DidCachingLoader,
        did_methods: IndexMap<String, Arc<dyn DidMethod>>,
    ) -> Self {
        let resolver = DidResolver {
            did_methods: did_methods.clone(),
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

    fn get_did_method_id(&self, did: &DidValue) -> Option<String> {
        self.did_methods
            .iter()
            .find(|(_, method)| {
                method
                    .get_capabilities()
                    .method_names
                    .iter()
                    .any(|v| v == did.method())
            })
            .map(|(id, _)| id.clone())
    }

    fn get_did_method_by_method_name(
        &self,
        method_name: &str,
    ) -> Option<(String, Arc<dyn DidMethod>)> {
        self.did_methods
            .iter()
            .find(|(_, method)| {
                method
                    .get_capabilities()
                    .method_names
                    .contains(&method_name.to_string())
            })
            .map(|(id, method)| (id.clone(), method.clone()))
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodProviderError> {
        let (content, _media_type) = self
            .caching_loader
            .get(did.as_str(), self.resolver.clone(), false)
            .await?;
        let dto: DidDocumentDTO = serde_json::from_slice(&content)?;
        Ok(dto.into())
    }

    fn supported_method_names(&self) -> Vec<String> {
        self.did_methods
            .values()
            .flat_map(|did_method| did_method.get_capabilities().method_names)
            .collect()
    }
}
