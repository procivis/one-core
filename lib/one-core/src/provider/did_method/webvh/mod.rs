//! Implementation of did:webvh.
//! https://identity.foundation/didwebvh/v0.3/

use std::sync::Arc;

use async_trait::async_trait;
use create::{DidDocKeys, UpdateKeys};
use shared_types::{DidId, DidValue};
use url::Url;

use super::error::DidMethodError;
use super::keys::Keys;
use super::model::{AmountOfKeys, DidCapabilities, DidDocument, Feature, Operation};
use super::{DidCreateKeys, DidCreated, DidMethod};
use crate::config::core_config::KeyAlgorithmType;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::key_storage::provider::KeyProvider;

mod common;
mod create;
mod resolver;
mod verification;

#[cfg(test)]
mod test;
#[derive(Debug, Default)]
pub struct Params {
    pub max_did_log_entry_check: Option<u32>,
    pub external_hosting_url: Option<String>,
}

pub struct DidWebVh {
    params: Params,
    core_base_url: Option<String>,
    client: Arc<dyn HttpClient>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_provider: Option<Arc<dyn KeyProvider>>,
}

impl DidWebVh {
    pub fn new(
        params: Params,
        core_base_url: Option<String>,
        client: Arc<dyn HttpClient>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Option<Arc<dyn KeyProvider>>,
    ) -> Self {
        Self {
            params,
            core_base_url,
            client,
            did_method_provider,
            key_provider,
        }
    }

    fn domain(&self, did_id: DidId) -> Result<String, DidMethodError> {
        if let Some(external_host) = self.params.external_hosting_url.as_ref() {
            Ok(format!("{external_host}:{did_id}"))
        } else {
            let base_url = self.core_base_url.as_ref().ok_or_else(|| {
                DidMethodError::CouldNotCreate("Missing core base url".to_string())
            })?;

            let url = Url::parse(base_url).map_err(|err| {
                DidMethodError::CouldNotCreate(format!("Invalid core base url: {err}"))
            })?;
            let mut domain = url
                .domain()
                .or(url.host_str())
                .ok_or_else(|| {
                    DidMethodError::CouldNotCreate(
                        "Invalid core base url: missing domain".to_string(),
                    )
                })?
                .to_owned();

            if let Some(port) = url.port() {
                // percent encode `:`
                domain.push_str("%3A");
                domain.push_str(&port.to_string());
            }

            domain.push_str(":ssi:did-webvh:v1:");
            domain.push_str(&did_id.to_string());

            Ok(domain)
        }
    }
}

#[async_trait]
impl DidMethod for DidWebVh {
    async fn create(
        &self,
        id: Option<DidId>,
        _params: &Option<serde_json::Value>,
        keys: Option<DidCreateKeys>,
    ) -> Result<DidCreated, DidMethodError> {
        let Some(key_provider) = self.key_provider.as_ref() else {
            return Err(DidMethodError::CouldNotCreate(
                "Missing key provider for did:webvh creation".to_string(),
            ));
        };

        let Some(keys) = keys else {
            return Err(DidMethodError::CouldNotCreate(
                "Missing keys for did:webvh".to_string(),
            ));
        };

        let update_keys = match keys.update_keys.as_deref() {
            None | Some([]) => {
                return Err(DidMethodError::CouldNotCreate(
                    "Missing update keys for did:webvh".to_string(),
                ))
            }
            Some([active, next @ ..]) => UpdateKeys { active, next },
        };

        let Some(did_id) = id else {
            return Err(DidMethodError::CouldNotCreate(
                "Missing did id for did:webvh".to_string(),
            ));
        };

        let did_doc_keys = DidDocKeys {
            authentication: keys.authentication,
            assertion_method: keys.assertion_method,
            key_agreement: keys.key_agreement,
            capability_invocation: keys.capability_invocation,
            capability_delegation: keys.capability_delegation,
        };

        let domain = self.domain(did_id)?;
        let (did, log) =
            create::create(&domain, did_doc_keys, update_keys, key_provider.as_ref()).await?;

        Ok(DidCreated {
            did,
            log: Some(log),
        })
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
            operations: vec![Operation::CREATE, Operation::RESOLVE],
            key_algorithms: vec![KeyAlgorithmType::Ecdsa],
            method_names: vec!["tdw".to_string()],
            features: vec![Feature::SupportsExternalHosting],
            supported_update_key_types: vec![KeyAlgorithmType::Eddsa],
        }
    }

    fn validate_keys(&self, keys: AmountOfKeys) -> bool {
        Keys::default().validate_keys(keys)
    }

    fn get_keys(&self) -> Option<Keys> {
        Some(Keys::default())
    }
}
