use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use shared_types::DidValue;
use time::OffsetDateTime;

use crate::provider::caching_loader::{CachingLoader, ResolveResult, Resolver};
use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::did_method::error::DidMethodProviderError;
use crate::provider::did_method::DidMethod;

pub struct DidResolver {
    pub did_methods: HashMap<String, Arc<dyn DidMethod>>,
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
        let method = self.did_method_from_value(did_value)?;
        let did_value: DidValue = did_value
            .parse()
            .context("did parsing error")
            .map_err(|e| Self::Error::Other(e.to_string()))?;
        let document = method.resolve(&did_value).await?;
        let dto: DidDocumentDTO = document.into();

        Ok(ResolveResult::NewValue {
            content: serde_json::to_vec(&dto)?,
            media_type: None,
        })
    }
}

impl DidResolver {
    fn did_method_from_value(
        &self,
        did_value: &str,
    ) -> Result<&Arc<dyn DidMethod>, DidMethodProviderError> {
        let did_method_id = did_method_id_from_value(did_value)?;

        self.did_methods
            .get(&did_method_id)
            .ok_or(DidMethodProviderError::MissingProvider(did_method_id))
    }
}

pub fn did_method_id_from_value(did_value: &str) -> Result<String, DidMethodProviderError> {
    let mut parts = did_value.splitn(3, ':');

    let did_domain = parts
        .next()
        .ok_or(DidMethodProviderError::MissingDidMethodNameInDidValue)?;

    if did_domain != "did" {
        return Err(DidMethodProviderError::DidValueValidationError);
    }

    let did_method = parts
        .next()
        .ok_or(DidMethodProviderError::MissingDidMethodNameInDidValue)?;

    Ok(did_method.to_uppercase())
}

#[cfg(test)]
mod tests {
    use crate::provider::did_method::resolver::did_method_id_from_value;

    #[test]
    fn test_did_method_id_from_value() {
        assert!(did_method_id_from_value("did:test:q123").is_ok());
        assert!(did_method_id_from_value("sdid:test:q123").is_err());
        assert!(did_method_id_from_value(":test:q123").is_err());
    }
}
