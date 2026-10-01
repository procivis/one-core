//! Implementation of DID Universal Resolver.
//! https://github.com/decentralized-identity/universal-resolver/

use std::sync::Arc;

use async_trait::async_trait;
use proc_macros::Provider;
use serde::Deserialize;
use shared_types::{DidId, DidMethodId, DidValue};

use super::{DidCreated, DidKeys, DidUpdate};
use crate::model::key::Key;
use crate::proto::http_client::HttpClient;
use crate::provider::did_method::DidMethod;
use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::keys::Keys;
use crate::provider::did_method::model::{DidCapabilities, DidDocument, Operation};
use crate::provider::provider_directory::InitializationError;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolutionResponse {
    did_document: DidDocumentDTO,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Params {
    pub resolver_url: String,
    pub supported_method_names: Vec<String>,
}

#[derive(Provider)]
pub struct UniversalDidMethod {
    config_id: DidMethodId,
    params: Params,
    client: Arc<dyn HttpClient>,
}

impl UniversalDidMethod {
    pub fn new(
        config_id: DidMethodId,
        params: serde_json::Value,
        client: Arc<dyn HttpClient>,
    ) -> Result<Self, InitializationError> {
        let params = serde_json::from_value(params).map_err(|source| {
            InitializationError::InvalidParams {
                key: config_id.to_string(),
                source,
            }
        })?;

        Ok(Self {
            config_id,
            params,
            client,
        })
    }
}

#[async_trait]
impl DidMethod for UniversalDidMethod {
    async fn create(
        &self,
        _id: DidId,
        _params: &Option<serde_json::Value>,
        _keys: DidKeys,
    ) -> Result<DidCreated, DidMethodError> {
        Err(DidMethodError::OperationNotSupported)
    }

    async fn resolve(&self, did_value: &DidValue) -> Result<DidDocument, DidMethodError> {
        let url = format!("{}/1.0/identifiers/{}", self.params.resolver_url, did_value);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .and_then(|resp| resp.error_for_status())
            .map_err(|e| {
                DidMethodError::ResolutionError(format!("Could not fetch did document: {e}"))
            })?;

        Ok(response
            .json::<ResolutionResponse>()
            .map(|resp| resp.did_document)
            .map_err(|e| {
                DidMethodError::ResolutionError(format!("Could not deserialize response: {e}"))
            })?
            .into())
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
            operations: vec![Operation::RESOLVE],
            key_algorithms: vec![],
            method_names: self.params.supported_method_names.clone(),
            features: vec![],
            supported_update_key_types: vec![],
        }
    }

    fn get_keys(&self) -> Option<Keys> {
        None
    }

    fn get_reference_for_key(&self, _key: &Key) -> Result<String, DidMethodError> {
        unimplemented!()
    }

    fn config_name(&self) -> &DidMethodId {
        &self.config_id
    }
}

#[cfg(test)]
mod test;
