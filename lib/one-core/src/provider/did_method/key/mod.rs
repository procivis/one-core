//! Implementation of did:key.
//! https://w3c-ccg.github.io/did-method-key

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use shared_types::{DidId, DidValue};

use super::common::expect_one_key;
use super::{DidCreateKeys, DidCreated};
use crate::config::core_config::KeyAlgorithmType;
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
        keys: Option<DidCreateKeys>,
    ) -> Result<DidCreated, DidMethodError> {
        let keys = keys.ok_or(DidMethodError::ResolutionError("Missing keys".to_string()))?;
        let key = expect_one_key(&keys)?;

        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_name(&key.key_type)
            .ok_or(DidMethodError::KeyAlgorithmNotFound)?;
        let multibase = key_algorithm
            .reconstruct_key(&key.public_key, None, None)
            .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?
            .public_key_as_multibase()
            .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?;
        format!("did:key:{}", multibase)
            .parse()
            .map(|did| DidCreated { did, log: None })
            .context("did parsing error")
            .map_err(|e| DidMethodError::CouldNotCreate(e.to_string()))
    }

    async fn resolve(&self, did_value: &DidValue) -> Result<DidDocument, DidMethodError> {
        let decoded = decode_did(did_value)?;
        let key_type = match decoded.type_ {
            key_helpers::DidKeyType::Eddsa => "EDDSA",
            key_helpers::DidKeyType::Ecdsa => "ECDSA",
            key_helpers::DidKeyType::Bbs => "BBS_PLUS",
        };

        let jwk = self
            .key_algorithm_provider
            .key_algorithm_from_name(key_type)
            .ok_or(DidMethodError::KeyAlgorithmNotFound)?
            .reconstruct_key(&decoded.decoded_multibase, None, None)
            .map_err(|err| {
                DidMethodError::ResolutionError(format!(
                    "Could not create jwk representation: {err}"
                ))
            })?
            .public_key_as_jwk()
            .map_err(|err| {
                DidMethodError::ResolutionError(format!(
                    "Could not create jwk representation: {err}"
                ))
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
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::BbsPlus,
            ],
            method_names: vec!["key".to_string()],
            features: vec![],
            supported_update_key_types: vec![],
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
