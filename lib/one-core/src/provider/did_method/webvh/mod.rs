//! Implementation of did:webvh.
//! https://identity.foundation/didwebvh/v0.3/

use std::sync::Arc;

use async_trait::async_trait;
use shared_types::{DidId, DidValue};

use super::error::DidMethodError;
use super::keys::Keys;
use super::model::{AmountOfKeys, DidCapabilities, DidDocument, Operation};
use super::DidMethod;
use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;

mod resolver;
mod verification;

#[derive(Debug, Default)]
pub struct Params {
    pub max_did_log_entry_check: Option<u32>,
}

pub struct DidWebVh {
    params: Params,
    client: Arc<dyn HttpClient>,
    did_method_provider: Arc<dyn DidMethodProvider>,
}

impl DidWebVh {
    pub fn new(
        params: Params,
        client: Arc<dyn HttpClient>,
        did_method_provider: Arc<dyn DidMethodProvider>,
    ) -> Self {
        Self {
            params,
            client,
            did_method_provider,
        }
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
        resolver::resolve(
            did,
            &*self.client,
            &*self.did_method_provider,
            false,
            &self.params,
        )
        .await
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
            key_algorithms: vec![KeyAlgorithmType::Ecdsa],
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
