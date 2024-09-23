//! Implementation of did:key.

use std::sync::Arc;

use async_trait::async_trait;
use shared_types::{DidId, DidValue};

use crate::model::key::Key;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::key_helpers::{decode_did, generate_document};
use crate::provider::did_method::keys::Keys;
use crate::provider::did_method::model::{AmountOfKeys, DidCapabilities, DidDocument, Operation};
use crate::provider::did_method::{key_helpers, DidMethod};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

pub struct KeyDidMethod {
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl KeyDidMethod {
    pub fn new(key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>) -> Self {
        Self {
            key_algorithm_provider,
        }
    }
}

#[async_trait]
impl DidMethod for KeyDidMethod {
    async fn create(
        &self,
        _id: Option<DidId>,
        _params: &Option<serde_json::Value>,
        keys: Option<Vec<Key>>,
    ) -> Result<DidValue, DidMethodError> {
        let keys = keys.ok_or(DidMethodError::ResolutionError("Missing keys".to_string()))?;

        let key = match keys.as_slice() {
            [key] => key,
            [] => return Err(DidMethodError::CouldNotCreate("Missing key".to_string())),
            _ => return Err(DidMethodError::CouldNotCreate("Too many keys".to_string())),
        };

        let key_algorithm = self
            .key_algorithm_provider
            .get_key_algorithm(&key.key_type)
            .ok_or(DidMethodError::KeyAlgorithmNotFound)?;
        let multibase = key_algorithm
            .get_multibase(&key.public_key)
            .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?;
        Ok(format!("did:key:{}", multibase).into())
    }

    async fn resolve(&self, did_value: &DidValue) -> Result<DidDocument, DidMethodError> {
        let decoded = decode_did(did_value)?;
        let key_type = match decoded.type_ {
            key_helpers::DidKeyType::Eddsa => "EDDSA",
            key_helpers::DidKeyType::Ecdsa => "ES256",
            key_helpers::DidKeyType::Bbs => "BBS_PLUS",
        };

        let jwk = self
            .key_algorithm_provider
            .get_key_algorithm(key_type)
            .ok_or(DidMethodError::KeyAlgorithmNotFound)?
            .bytes_to_jwk(&decoded.decoded_multibase, None)
            .map_err(|_| {
                DidMethodError::ResolutionError("Could not create jwk representation".to_string())
            })?;

        generate_document(decoded, did_value, jwk)
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn can_be_deactivated(&self) -> bool {
        false
    }

    fn get_capabilities(&self) -> DidCapabilities {
        DidCapabilities {
            operations: vec![Operation::RESOLVE, Operation::CREATE],
            key_algorithms: vec![
                "ES256".to_string(),
                "EDDSA".to_string(),
                "BBS_PLUS".to_string(),
            ],
        }
    }

    fn validate_keys(&self, keys: AmountOfKeys) -> bool {
        Keys::default().validate_keys(keys)
    }

    fn get_keys(&self) -> Option<Keys> {
        Some(Keys::default())
    }
}

#[cfg(test)]
mod test;
