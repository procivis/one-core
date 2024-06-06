use super::dto::{AmountOfKeys, DidDocumentDTO, Keys};
use super::{DidCapabilities, DidMethodError, Operation};
use crate::config::core_config::{self, DidType, Fields};
use crate::model::key::Key;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use shared_types::{DidId, DidValue};
use url::Url;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde(default)]
    keys: Keys,
    resolve_to_insecure_http: Option<bool>,
}

pub struct WebDidMethod {
    pub did_base_string: Option<String>,
    pub client: reqwest::Client,
    pub params: Params,
}

impl WebDidMethod {
    pub fn new(base_url: &Option<String>, params: Params) -> Result<Self, DidMethodError> {
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
            client: reqwest::Client::new(),
            params,
        })
    }
}

#[async_trait]
impl super::DidMethod for WebDidMethod {
    async fn create(
        &self,
        id: &DidId,
        _params: &Option<serde_json::Value>,
        _key: &[Key],
    ) -> Result<DidValue, DidMethodError> {
        let did_base_string =
            self.did_base_string
                .as_ref()
                .ok_or(DidMethodError::CouldNotCreate(
                    "Missing base_url".to_string(),
                ))?;

        let did_value = format!("{did_base_string}:{id}");
        Ok(DidValue::from(did_value))
    }

    async fn resolve(&self, did_value: &DidValue) -> Result<DidDocumentDTO, DidMethodError> {
        let url = did_value_to_url(did_value, self.params.resolve_to_insecure_http)?;

        Ok(fetch_did_web_document(url, &self.client).await?)
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
                "ES256".to_string(),
                "EDDSA".to_string(),
                "BBS_PLUS".to_string(),
                "DILITHIUM".to_string(),
            ],
        }
    }

    fn validate_keys(&self, keys: AmountOfKeys) -> bool {
        self.params.keys.validate_keys(keys)
    }

    fn visit_config_fields(&self, fields: &Fields<DidType>) -> Fields<DidType> {
        Fields {
            capabilities: Some(json!(self.get_capabilities())),
            params: Some(core_config::Params {
                public: Some(json!({
                    "keys": self.params.keys,
                })),
                private: None,
            }),
            ..fields.clone()
        }
    }
}

async fn fetch_did_web_document(
    url: Url,
    client: &reqwest::Client,
) -> Result<DidDocumentDTO, DidMethodError> {
    let response = client.get(url).send().await.map_err(|e| {
        DidMethodError::ResolutionError(format!("Could not fetch did document: {e}"))
    })?;

    let response = response.error_for_status().map_err(|e| {
        DidMethodError::ResolutionError(format!("Could not fetch did document: {e}"))
    })?;

    let response_value = response.text().await.map_err(|e| {
        DidMethodError::ResolutionError(format!("Could not fetch did document: {e}"))
    })?;

    serde_json::from_str(&response_value)
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
