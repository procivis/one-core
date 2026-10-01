//! Implementation of did:web.
//! https://w3c-ccg.github.io/did-method-web/

use std::sync::Arc;

use async_trait::async_trait;
use proc_macros::Provider;
use serde::Deserialize;
use shared_types::{DidId, DidMethodId, DidValue};
use url::Url;

use super::{DidCreated, DidKeys, DidUpdate};
use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::proto::http_client::HttpClient;
use crate::provider::did_method::DidMethod;
use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::keys::Keys;
use crate::provider::did_method::model::{DidCapabilities, DidDocument, Operation};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Params {
    #[serde(default)]
    pub keys: Keys,
    pub resolve_to_insecure_http: Option<bool>,
}

#[derive(Provider)]
pub struct WebDidMethod {
    config_id: DidMethodId,
    did_base_string: Option<String>,
    client: Arc<dyn HttpClient>,
    params: Params,
}

impl WebDidMethod {
    pub fn new(
        config_id: DidMethodId,
        base_url: &Option<String>,
        client: Arc<dyn HttpClient>,
        params: serde_json::Value,
    ) -> Result<Self, DidMethodError> {
        let did_base_string = if let Some(base_url) = base_url {
            let url = Url::parse(base_url)?;

            let mut host_str = url
                .host_str()
                .ok_or(DidMethodError::InitializationError(
                    "Missing host".to_string(),
                ))?
                .to_owned();

            if let Some(port) = url.port() {
                host_str.push_str(&format!("%3A{port}"));
            }

            let did_base_string = format!("did:web:{host_str}:ssi:did-web:v1");

            Some(did_base_string)
        } else {
            None
        };

        let params = serde_json::from_value(params)?;

        Ok(Self {
            config_id,
            did_base_string,
            client,
            params,
        })
    }
}

#[async_trait]
impl DidMethod for WebDidMethod {
    async fn create(
        &self,
        id: DidId,
        _params: &Option<serde_json::Value>,
        _keys: DidKeys,
    ) -> Result<DidCreated, DidMethodError> {
        let did_base_string =
            self.did_base_string
                .as_ref()
                .ok_or(DidMethodError::InitializationError(
                    "Missing base_url".to_string(),
                ))?;

        let did_value = format!("{did_base_string}:{id}");

        Ok(did_value.parse().map(|did| DidCreated { did, log: None })?)
    }

    async fn resolve(&self, did_value: &DidValue) -> Result<DidDocument, DidMethodError> {
        let url = did_value_to_url(did_value, self.params.resolve_to_insecure_http)?;

        Ok(fetch_did_web_document(url, &self.client).await?.into())
    }

    async fn deactivate(
        &self,
        _id: DidId,
        _keys: DidKeys,
        _log: Option<String>,
    ) -> Result<DidUpdate, DidMethodError> {
        Ok(DidUpdate {
            deactivated: Some(true),
            log: None,
        })
    }

    async fn update(
        &self,
        _id: DidId,
        _keys: DidKeys,
        _new_keys: DidKeys,
        _log: Option<String>,
    ) -> Result<DidUpdate, DidMethodError> {
        // The published did:web document is generated from the persisted key associations.
        Ok(DidUpdate::default())
    }

    fn get_capabilities(&self) -> DidCapabilities {
        let mut operations = vec![Operation::RESOLVE, Operation::DEACTIVATE, Operation::UPDATE];
        if self.did_base_string.is_some() {
            operations.push(Operation::CREATE);
        }

        DidCapabilities {
            operations,
            key_algorithms: vec![
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::BbsPlus,
                KeyAlgorithmType::MlDsa,
            ],
            method_names: vec!["web".to_string()],
            features: vec![],
            supported_update_key_types: vec![],
        }
    }

    fn get_keys(&self) -> Option<Keys> {
        Some(self.params.keys.to_owned())
    }

    fn get_reference_for_key(&self, key: &Key) -> Result<String, DidMethodError> {
        Ok(format!("key-{}", key.id))
    }

    fn config_name(&self) -> &DidMethodId {
        &self.config_id
    }
}

async fn fetch_did_web_document(
    url: Url,
    client: &Arc<dyn HttpClient>,
) -> Result<DidDocumentDTO, DidMethodError> {
    let response = client.get(url.as_str()).send().await.map_err(|e| {
        DidMethodError::ResolutionError(format!("Could not fetch did document: {e}"))
    })?;

    let response = response.error_for_status().map_err(|e| {
        DidMethodError::ResolutionError(format!("Could not fetch did document: {e}"))
    })?;

    serde_json::from_slice(&response.body)
        .map_err(|e| DidMethodError::ResolutionError(format!("Could not fetch did document: {e}")))
}

fn did_value_to_url(
    did_value: &DidValue,
    resolve_to_http: Option<bool>,
) -> Result<Url, DidMethodError> {
    let core_value =
        did_value
            .as_str()
            .strip_prefix("did:web:")
            .ok_or(DidMethodError::ResolutionError(
                "Incorrect did value".to_owned(),
            ))?;

    let mut path_parts = core_value.split(':');
    let host = path_parts.next().ok_or(DidMethodError::ResolutionError(
        "Missing host part in a did value".to_string(),
    ))?;

    let scheme = match resolve_to_http {
        Some(true) => "http",
        _ => "https",
    };

    // That's the only percent encoded character we expect here
    let host = format!("{scheme}://{}", host.replace("%3A", ":"));

    let mut url = Url::parse(&host).map_err(|e| DidMethodError::ResolutionError(e.to_string()))?;
    url.set_scheme(scheme)
        .map_err(|_| DidMethodError::ResolutionError("Could not set url scheme".to_string()))?;

    let remaining_parts: Vec<&str> = path_parts.collect();

    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| DidMethodError::ResolutionError("Error".to_string()))?;

        if remaining_parts.is_empty() {
            segments.push(".well-known");
        } else {
            segments.extend(remaining_parts);
        }

        segments.push("did.json");
    }

    Ok(url)
}
#[cfg(test)]
mod test;
