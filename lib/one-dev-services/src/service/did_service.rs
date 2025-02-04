//! A service for creating DIDs and resolving DIDs to their DID document.
//!
//! See the **/examples** directory in the [repository][repo] for an
//! example implementation.
//!
//! [repo]: https://github.com/procivis/one-open-core

use std::sync::Arc;

use one_core::provider::did_method::error::DidMethodProviderError;
use one_core::provider::did_method::model::DidDocument;
use one_core::provider::did_method::provider::DidMethodProvider;
use one_core::provider::did_method::DidMethod;
use shared_types::DidValue;

#[derive(Clone)]
pub struct DidService {
    pub did_provider: Arc<dyn DidMethodProvider>,
    pub fallback_method: Option<Arc<dyn DidMethod>>,
}

impl DidService {
    pub fn new(
        did_provider: Arc<dyn DidMethodProvider>,
        fallback_method: Option<Arc<dyn DidMethod>>,
    ) -> Self {
        Self {
            did_provider,
            fallback_method,
        }
    }

    pub fn get_did_method(&self, did_method_id: &str) -> Option<Arc<dyn DidMethod>> {
        self.did_provider.get_did_method(did_method_id)
    }

    pub async fn resolve_did(
        &self,
        did: &DidValue,
        allow_fallback_resolver: bool,
    ) -> Result<DidDocument, DidMethodProviderError> {
        let resolution = self.did_provider.resolve(did).await;

        if !allow_fallback_resolver {
            return resolution;
        }

        match resolution {
            Ok(x) => Ok(x),
            Err(DidMethodProviderError::MissingProvider(x)) => {
                if let Some(fallback) = &self.fallback_method {
                    Ok(fallback.resolve(did).await?)
                } else {
                    Err(DidMethodProviderError::MissingProvider(x))
                }
            }
            Err(x) => Err(x),
        }
    }
}
