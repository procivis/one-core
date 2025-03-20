//! Implementation of did:web.
//! https://w3c-ccg.github.io/did-method-web/

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use shared_types::{DidId, DidValue};
use url::Url;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::keys::Keys;
use crate::provider::did_method::model::{AmountOfKeys, DidCapabilities, DidDocument, Operation};
use crate::provider::did_method::DidMethod;
use crate::provider::http_client::HttpClient;

#[derive(Debug, Clone, Default)]
pub struct Params {
    pub keys: Keys,
    pub resolve_to_insecure_http: Option<bool>,
}

pub struct WebDidMethod {
    pub did_base_string: Option<String>,
    pub client: Arc<dyn HttpClient>,
    pub params: Params,
}

impl WebDidMethod {
    pub fn new(
        base_url: &Option<String>,
        client: Arc<dyn HttpClient>,
        params: Params,
    ) -> Result<Self, DidMethodError> {
        let did_base_string = if let Some(base_url) = base_url {
            let url =
                Url::parse(base_url).map_err(|e| DidMethodError::CouldNotCreate(e.to_string()))?;

            let mut host_str = url
                .host_str()
                .ok_or(DidMethodError::CouldNotCreate("Missing host".to_string()))?
                .to_owned();

            if let Some(port) = url.port() {
                host_str.push_str(&format!("%3A{port}"));
            }

            let did_base_string = format!("did:web:{}:ssi:did-web:v1", host_str);

            Some(did_base_string)
        } else {
            None
        };

        Ok(Self {
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
        id: Option<DidId>,
        _params: &Option<serde_json::Value>,
        _key: Option<Vec<Key>>,
    ) -> Result<DidValue, DidMethodError> {
        let did_base_string =
            self.did_base_string
                .as_ref()
                .ok_or(DidMethodError::CouldNotCreate(
                    "Missing base_url".to_string(),
                ))?;

        let id = id.ok_or(DidMethodError::ResolutionError(
            "Missing did id".to_string(),
        ))?;

        let did_value = format!("{did_base_string}:{id}");
        Ok(did_value
            .parse()
            .context("did parsing error")
            .map_err(|e| DidMethodError::CouldNotCreate(e.to_string()))?)
    }

    async fn resolve(&self, did_value: &DidValue) -> Result<DidDocument, DidMethodError> {
        let url = did_value_to_url(did_value, self.params.resolve_to_insecure_http)?;

        Ok(fetch_did_web_document(url, &self.client).await?.into())
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn can_be_deactivated(&self) -> bool {
        true
    }

    fn get_capabilities(&self) -> DidCapabilities {
        DidCapabilities {
            operations: vec![Operation::RESOLVE, Operation::CREATE, Operation::DEACTIVATE],
            key_algorithms: vec![
                KeyAlgorithmType::Es256,
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::BbsPlus,
                KeyAlgorithmType::Dilithium,
            ],
            method_names: vec!["web".to_string()],
        }
    }

    fn validate_keys(&self, keys: AmountOfKeys) -> bool {
        self.params.keys.validate_keys(keys)
    }

    fn get_keys(&self) -> Option<Keys> {
        Some(self.params.keys.to_owned())
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
