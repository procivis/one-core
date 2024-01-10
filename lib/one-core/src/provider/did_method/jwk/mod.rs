use self::helpers::{encode_to_did, extract_jwk, generate_document};

use super::{dto::DidDocumentDTO, DidCapabilities, DidMethodError};
use crate::{model::key::Key, provider::key_algorithm::provider::KeyAlgorithmProvider};

use async_trait::async_trait;
use shared_types::{DidId, DidValue};
use std::sync::Arc;

mod helpers;

pub struct JWKDidMethod {
    capabilities: DidCapabilities,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
}

impl JWKDidMethod {
    #[allow(clippy::new_without_default)]
    pub fn new(
        capabilities: DidCapabilities,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
    ) -> Self {
        Self {
            capabilities,
            key_algorithm_provider,
        }
    }
}

#[async_trait]
impl super::DidMethod for JWKDidMethod {
    fn get_method(&self) -> String {
        "jwk".to_string()
    }

    async fn create(
        &self,
        _id: &DidId,
        _params: &Option<serde_json::Value>,
        key: &Option<Key>,
    ) -> Result<DidValue, DidMethodError> {
        let key = key
            .as_ref()
            .ok_or(DidMethodError::CouldNotCreate("Missing key".to_string()))?;
        let key_algorithm = self
            .key_algorithm_provider
            .get_key_algorithm(&key.key_type)
            .map_err(|_| DidMethodError::KeyAlgorithmNotFound)?;
        let jwk = key_algorithm
            .bytes_to_jwk(&key.public_key)
            .map_err(|e| DidMethodError::CouldNotCreate(e.to_string()))?;

        encode_to_did(&jwk)
    }

    fn check_authorization(&self) -> bool {
        todo!()
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocumentDTO, DidMethodError> {
        let jwk = extract_jwk(did)?;
        Ok(generate_document(did, jwk))
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn can_be_deactivated(&self) -> bool {
        false
    }

    fn get_capabilities(&self) -> DidCapabilities {
        self.capabilities.to_owned()
    }
}

#[cfg(test)]
mod test;
