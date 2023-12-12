mod mapper;

use async_trait::async_trait;
use did_key::{Config, DIDCore, KeyMaterial};
use shared_types::{DidId, DidValue};
use std::sync::Arc;

use self::mapper::{categorize_did, convert_document};

use super::{dto::DidDocumentDTO, DidMethodError};
use crate::{model::key::Key, provider::key_algorithm::provider::KeyAlgorithmProvider};

pub struct KeyDidMethod {
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
    pub params: DidKeyParams,
}

pub struct DidKeyParams;

impl KeyDidMethod {
    pub fn new(
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
        params: DidKeyParams,
    ) -> Self {
        Self {
            key_algorithm_provider,
            params,
        }
    }
}

#[async_trait]
impl super::DidMethod for KeyDidMethod {
    fn get_method(&self) -> String {
        "key".to_string()
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
        let multibase = key_algorithm.get_multibase(&key.public_key);
        // todo(mite): add constructor for this
        let did_value: DidValue = match format!("did:key:{}", multibase).parse() {
            Ok(v) => v,
            Err(err) => match err {},
        };
        Ok(did_value)
    }

    fn check_authorization(&self) -> bool {
        todo!()
    }

    async fn resolve(&self, did_value: &DidValue) -> Result<DidDocumentDTO, DidMethodError> {
        let key_type = categorize_did(did_value)?;

        let resolved = did_key::resolve(did_value.as_str())
            .map_err(|_| DidMethodError::ResolutionError("Failed to resolve".to_string()))?;

        let public_key_bytes = resolved.public_key_bytes();

        let algorithm = self
            .key_algorithm_provider
            .get_key_algorithm(&key_type)
            .map_err(|_| DidMethodError::ResolutionError("Unsupported algorithm".to_string()))?;

        let public_key_jwk = algorithm.bytes_to_jwk(&public_key_bytes).map_err(|_| {
            DidMethodError::ResolutionError("Could not create jwk representation".to_string())
        })?;

        let document = resolved.get_did_document(Config {
            use_jose_format: true,
            serialize_secrets: false,
        });

        convert_document(document, public_key_jwk)
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn can_be_deactivated(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod test;
