//! Implementation of did:jwk.
//! https://github.com/quartzjer/did-jwk/blob/main/spec.md

use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};

pub(crate) mod jwk_helpers;

use proc_macros::Provider;
use shared_types::{DidId, DidMethodId, DidValue};
use standardized_types::jwk::PublicJwk;

use super::common::expect_one_key;
use super::{DidCreated, DidKeys, DidUpdate};
use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::model::key::Key;
use crate::provider::did_method::DidMethod;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::jwk::jwk_helpers::{extract_jwk, generate_document};
use crate::provider::did_method::keys::Keys;
use crate::provider::did_method::model::{DidCapabilities, DidDocument, Operation};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

#[derive(Provider)]
pub struct JWKDidMethod {
    config_id: DidMethodId,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl JWKDidMethod {
    pub fn new(
        config_id: DidMethodId,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Self {
        Self {
            config_id,
            key_algorithm_provider,
        }
    }
}

#[async_trait]
impl DidMethod for JWKDidMethod {
    async fn create(
        &self,
        _id: DidId,
        _params: &Option<serde_json::Value>,
        keys: DidKeys,
    ) -> Result<DidCreated, DidMethodError> {
        let key = expect_one_key(&keys)?;

        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_key(key)
            .error_while("getting key algorithm")?;

        let jwk = key_algorithm
            .reconstruct_key(&key.public_key, None, None)
            .error_while("reconstructing key")?
            .public_key_as_jwk()
            .error_while("getting JWK")?;

        encode_to_did(&jwk).map(|did| DidCreated { did, log: None })
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodError> {
        let jwk = extract_jwk(did)?;
        Ok(generate_document(did, jwk))
    }

    async fn update(
        &self,
        _did_id: DidId,
        _keys: DidKeys,
        _new_keys: DidKeys,
        _log: Option<String>,
    ) -> Result<DidUpdate, DidMethodError> {
        Err(DidMethodError::OperationNotSupported)
    }

    async fn deactivate(
        &self,
        _id: DidId,
        _keys: DidKeys,
        _log: Option<String>,
    ) -> Result<DidUpdate, DidMethodError> {
        Err(DidMethodError::OperationNotSupported)
    }

    fn get_capabilities(&self) -> DidCapabilities {
        DidCapabilities {
            operations: vec![Operation::RESOLVE, Operation::CREATE],
            key_algorithms: vec![
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::BbsPlus,
                KeyAlgorithmType::MlDsa,
            ],
            method_names: vec!["jwk".to_string()],
            features: vec![],
            supported_update_key_types: vec![],
        }
    }

    fn get_keys(&self) -> Option<Keys> {
        Some(Keys::default())
    }

    fn get_reference_for_key(&self, _key: &Key) -> Result<String, DidMethodError> {
        Ok("0".to_string())
    }

    fn config_name(&self) -> &DidMethodId {
        &self.config_id
    }
}

pub fn encode_to_did(jwk: &PublicJwk) -> Result<DidValue, DidMethodError> {
    let jwk = serde_json::to_string(jwk)?;
    let encoded = Base64UrlSafeNoPadding::encode_to_string(jwk)?;
    Ok(format!("did:jwk:{encoded}").parse()?)
}

#[cfg(test)]
mod test;
