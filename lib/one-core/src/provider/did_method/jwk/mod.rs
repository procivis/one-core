//! Implementation of did:jwk.
//! https://github.com/quartzjer/did-jwk/blob/main/spec.md

use std::sync::Arc;

use async_trait::async_trait;

pub(crate) mod jwk_helpers;

use shared_types::{DidId, DidValue};

use super::common::expect_one_key;
use super::{DidCreateKeys, DidCreated};
use crate::config::core_config::KeyAlgorithmType;
use crate::provider::did_method::DidMethod;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::jwk::jwk_helpers::{
    encode_to_did, extract_jwk, generate_document,
};
use crate::provider::did_method::keys::Keys;
use crate::provider::did_method::model::{AmountOfKeys, DidCapabilities, DidDocument, Operation};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

pub struct JWKDidMethod {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl JWKDidMethod {
    #[allow(clippy::new_without_default)]
    pub fn new(key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>) -> Self {
        Self {
            key_algorithm_provider,
        }
    }
}

#[async_trait]
impl DidMethod for JWKDidMethod {
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
        let jwk = key_algorithm
            .reconstruct_key(&key.public_key, None, None)
            .map_err(|e| DidMethodError::CouldNotCreate(e.to_string()))?
            .public_key_as_jwk()
            .map_err(|e| DidMethodError::CouldNotCreate(e.to_string()))?;

        encode_to_did(&jwk.into()).map(|did| DidCreated { did, log: None })
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodError> {
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
        DidCapabilities {
            operations: vec![Operation::RESOLVE, Operation::CREATE],
            key_algorithms: vec![
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::BbsPlus,
                KeyAlgorithmType::Dilithium,
            ],
            method_names: vec!["jwk".to_string()],
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
