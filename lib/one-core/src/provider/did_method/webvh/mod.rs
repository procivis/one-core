use std::sync::Arc;

use async_trait::async_trait;
use shared_types::{DidId, DidValue};

use super::error::DidMethodError;
use super::keys::Keys;
use super::model::{AmountOfKeys, DidCapabilities, DidDocument, Operation};
use super::DidMethod;
use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::provider::http_client::HttpClient;

mod resolver;

#[derive(Debug)]
pub struct Params {
    pub max_did_log_entry_check: u32,
}

pub struct DidWebVh {
    #[allow(dead_code)]
    params: Params,
    client: Arc<dyn HttpClient>,
}

impl DidWebVh {
    pub fn new(params: Params, client: Arc<dyn HttpClient>) -> Self {
        Self { params, client }
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

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodError> {
        resolver::resolve(did, &*self.client, false).await
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
            key_algorithms: vec![KeyAlgorithmType::Es256],
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
