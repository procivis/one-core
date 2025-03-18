use async_trait::async_trait;
use shared_types::{DidId, DidValue};

use super::error::DidMethodError;
use super::keys::Keys;
use super::model::{AmountOfKeys, DidCapabilities, DidDocument, Operation};
use super::DidMethod;
use crate::model::key::Key;

#[derive(Debug)]
pub struct Params {
    pub max_did_log_entry_check: u32,
}

pub struct DidWebVh {
    pub params: Params,
}

impl DidWebVh {
    pub fn new(params: Params) -> Self {
        Self { params }
    }
}

#[async_trait]
impl DidMethod for DidWebVh {
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
            operations: vec![Operation::RESOLVE],
            key_algorithms: vec!["ES256".to_string()],
            method_names: vec!["tdw".to_string()],
        }
    }

    fn validate_keys(&self, _keys: AmountOfKeys) -> bool {
        todo!()
    }

    fn get_keys(&self) -> Option<Keys> {
        None
    }
}
