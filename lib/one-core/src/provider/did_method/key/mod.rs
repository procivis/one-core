//! Implementation of did:key.
//! https://w3c-ccg.github.io/did-method-key

use std::sync::Arc;

use async_trait::async_trait;
use proc_macros::Provider;
use shared_types::{DidId, DidMethodId, DidValue};

use super::common::expect_one_key;
use super::{DidCreated, DidKeys, DidUpdate};
use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::model::key::Key;
use crate::provider::did_method::DidMethod;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::key_helpers::{
    DecodedDidKeyMaterial, decode_did, generate_document,
};
use crate::provider::did_method::keys::Keys;
use crate::provider::did_method::model::{DidCapabilities, DidDocument, Operation};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

#[derive(Provider)]
pub struct KeyDidMethod {
    config_id: DidMethodId,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl KeyDidMethod {
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
impl DidMethod for KeyDidMethod {
    async fn create(
        &self,
        _id: DidId,
        _params: &Option<serde_json::Value>,
        keys: DidKeys,
    ) -> Result<DidCreated, DidMethodError> {
        let key = expect_one_key(&keys)?;

        let multibase = self.get_multibase(key)?;
        let did = format!("did:key:{multibase}").parse()?;

        Ok(DidCreated { did, log: None })
    }

    async fn resolve(&self, did_value: &DidValue) -> Result<DidDocument, DidMethodError> {
        let decoded = decode_did(did_value)?;

        let jwk = match &decoded.key {
            DecodedDidKeyMaterial::Raw { r#type, public_key } => self
                .key_algorithm_provider
                .key_algorithm_from_type(*r#type)?
                .reconstruct_key(public_key, None, None)
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
                })?,
            DecodedDidKeyMaterial::JcsJwk(jwk) => jwk.clone(),
        };

        Ok(generate_document(decoded, did_value, jwk))
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
            ],
            method_names: vec!["key".to_string()],
            features: vec![],
            supported_update_key_types: vec![],
        }
    }

    fn get_keys(&self) -> Option<Keys> {
        Some(Keys::default())
    }

    fn get_reference_for_key(&self, key: &Key) -> Result<String, DidMethodError> {
        self.get_multibase(key)
    }

    fn config_name(&self) -> &DidMethodId {
        &self.config_id
    }
}

impl KeyDidMethod {
    fn get_multibase(&self, key: &Key) -> Result<String, DidMethodError> {
        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_key(key)
            .error_while("getting key algorithm")?;
        let multibase = key_algorithm
            .reconstruct_key(&key.public_key, None, None)
            .error_while("reconstructing key")?
            .public_key_as_multibase()
            .error_while("getting multibase")?;
        Ok(multibase)
    }
}

#[cfg(test)]
mod test;
