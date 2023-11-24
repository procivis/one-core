use std::str::FromStr;

use super::DidMethodError;
use crate::model::did::Did;
use crate::model::key::Key;

use async_trait::async_trait;
use shared_types::{DidId, DidValue};
use url::Url;

pub struct WebDidMethod {
    did_base_string: Option<String>,
}

impl WebDidMethod {
    pub fn new(base_url: &Option<String>) -> Result<Self, DidMethodError> {
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

        Ok(Self { did_base_string })
    }
}

#[async_trait]
impl super::DidMethod for WebDidMethod {
    fn get_method(&self) -> String {
        "web".to_string()
    }

    async fn create(
        &self,
        id: &DidId,
        _params: &Option<serde_json::Value>,
        _key: &Option<Key>,
    ) -> Result<DidValue, DidMethodError> {
        let did_base_string =
            self.did_base_string
                .as_ref()
                .ok_or(DidMethodError::CouldNotCreate(
                    "Missing base_url".to_string(),
                ))?;

        let did_value = format!("{did_base_string}:{id}");
        Ok(DidValue::from_str(&did_value).unwrap())
    }

    fn check_authorization(&self) -> bool {
        todo!()
    }

    async fn resolve(&self, _did: &DidValue) -> Result<Did, DidMethodError> {
        todo!()
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn can_be_deactivated(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod test;
