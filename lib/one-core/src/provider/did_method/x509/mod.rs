//! Implementation of did:x509.
//! https://github.com/microsoft/did-x509/blob/main/specification.md

use async_trait::async_trait;
use shared_types::{DidId, DidValue};

use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::keys::Keys;
use crate::provider::did_method::model::{AmountOfKeys, DidCapabilities, DidDocument, Operation};
use crate::provider::did_method::DidMethod;

pub struct X509Method {}

impl X509Method {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl DidMethod for X509Method {
    async fn create(
        &self,
        _id: Option<DidId>,
        _params: &Option<serde_json::Value>,
        _keys: Option<Vec<Key>>,
    ) -> Result<DidValue, DidMethodError> {
        todo!()
    }

    async fn resolve(&self, _did: &DidValue) -> Result<DidDocument, DidMethodError> {
        todo!()
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
            key_algorithms: vec![KeyAlgorithmType::Ecdsa, KeyAlgorithmType::Eddsa],
            method_names: vec!["x509".to_string()],
        }
    }

    fn validate_keys(&self, _keys: AmountOfKeys) -> bool {
        todo!()
    }

    fn get_keys(&self) -> Option<Keys> {
        None
    }
}
