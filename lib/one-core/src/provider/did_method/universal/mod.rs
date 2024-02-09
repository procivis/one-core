use async_trait::async_trait;
use serde::Deserialize;
use shared_types::{DidId, DidValue};

use crate::model::key::Key;

use super::{dto::DidDocumentDTO, AmountOfKeys, DidCapabilities, DidMethodError, Operation};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolutionResponse {
    did_document: DidDocumentDTO,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    resolver_url: String,
}

pub struct UniversalDidMethod {
    pub params: Params,
    pub client: reqwest::Client,
}

impl UniversalDidMethod {
    pub fn new(params: Params) -> Self {
        Self {
            params,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl super::DidMethod for UniversalDidMethod {
    fn get_method(&self) -> String {
        todo!()
    }

    async fn create(
        &self,
        _id: &DidId,
        _params: &Option<serde_json::Value>,
        _key: &Option<Key>,
    ) -> Result<DidValue, DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn check_authorization(&self) -> bool {
        todo!()
    }

    async fn resolve(&self, did_value: &DidValue) -> Result<DidDocumentDTO, DidMethodError> {
        let url = format!(
            "{}/1.0/identifiers/{}",
            self.params.resolver_url,
            did_value.as_str(),
        );

        let response = self
            .client
            .get(url)
            .send()
            .await
            .and_then(|resp| resp.error_for_status())
            .map_err(|e| {
                DidMethodError::ResolutionError(format!("Could not fetch did document: {e}"))
            })?;

        response
            .json::<ResolutionResponse>()
            .await
            .map(|resp| resp.did_document)
            .map_err(|e| {
                DidMethodError::ResolutionError(format!("Could not deserialize response: {e}"))
            })
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
            key_algorithms: vec![],
        }
    }

    fn validate_keys(&self, _keys: AmountOfKeys) -> bool {
        unimplemented!()
    }
}

#[cfg(test)]
mod test;
