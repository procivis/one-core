use std::sync::Arc;

use async_trait::async_trait;
use indexmap::IndexMap;
use shared_types::DidValue;
use time::OffsetDateTime;

use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::provider::caching_loader::{CachingLoader, ResolveResult, Resolver};
use crate::provider::did_method::DidMethod;
use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::did_method::error::{DidMethodError, DidMethodProviderError};
use crate::service::error::MissingProviderError;

pub struct DidResolver {
    pub did_methods: IndexMap<String, Arc<dyn DidMethod>>,
}

pub type DidCachingLoader = CachingLoader<DidMethodProviderError>;

#[async_trait]
impl Resolver for DidResolver {
    type Error = DidMethodProviderError;

    async fn do_resolve(
        &self,
        did_value: &str,
        _previous: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        let did_value: DidValue = did_value
            .parse()
            .map_err(DidMethodError::DidValueError)
            .error_while("parsing DID value")?;
        let method = self.did_method_from_value(&did_value)?;
        let document = method
            .resolve(&did_value)
            .await
            .error_while("resolving did")?;
        let dto: DidDocumentDTO = document.into();

        Ok(ResolveResult::NewValue {
            content: serde_json::to_vec(&dto)?,
            media_type: None,
            expiry_date: None,
        })
    }
}

impl DidResolver {
    fn did_method_from_value(
        &self,
        did_value: &DidValue,
    ) -> Result<&Arc<dyn DidMethod>, DidMethodProviderError> {
        Ok(self
            .did_methods
            .values()
            .find(|method| {
                method
                    .get_capabilities()
                    .method_names
                    .iter()
                    .any(|val| val == did_value.method())
            })
            .ok_or(
                MissingProviderError::DidMethod(did_value.method().to_string())
                    .error_while("getting did provider"),
            )?)
    }
}
