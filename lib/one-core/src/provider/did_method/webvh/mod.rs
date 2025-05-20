//! Implementation of did:webvh.
//! https://identity.foundation/didwebvh/v0.3/

use std::sync::Arc;

use async_trait::async_trait;
use create::{DidDocKeys, UpdateKeys};
use serde::Deserialize;
use shared_types::{DidId, DidValue};
use url::Url;

use super::keys::Keys;
use super::model::{AmountOfKeys, DidCapabilities, DidDocument, Feature, Operation};
use super::{DidCreated, DidKeys, DidMethod, DidUpdate};
use crate::config::core_config::KeyAlgorithmType;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::did_method::webvh::common::{
    build_proof, canonicalize_multihash_encode, make_keyref, now_utc, update_version,
};
use crate::provider::did_method::webvh::deserialize::DidLogEntry;
use crate::provider::did_method::webvh::mapper::url_to_did;
use crate::provider::http_client::HttpClient;
use crate::provider::key_storage::provider::KeyProvider;

mod common;
mod create;
mod resolver;
mod serialize;
mod verification;

mod deserialize;
mod mapper;
#[cfg(test)]
mod test;

#[derive(Debug, Default)]
pub struct Params {
    pub keys: Keys,
    pub max_did_log_entry_check: Option<u32>,
    pub resolve_to_insecure_http: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidCreateParams {
    external_hosting_url: Url,
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

    fn domain(
        &self,
        did_id: DidId,
        external_hosting_url: Option<Url>,
    ) -> Result<String, DidMethodError> {
        if let Some(external_host) = external_hosting_url {
            return url_to_did(external_host);
        }

        let base_url = self
            .core_base_url
            .as_ref()
            .ok_or_else(|| DidMethodError::CouldNotCreate("Missing core base url".to_string()))?;

        let url = Url::parse(base_url).map_err(|err| {
            DidMethodError::CouldNotCreate(format!("Invalid core base url: {err}"))
        })?;

        let mut domain = url_to_did(url)?;
        domain.push_str(":ssi:did-webvh:v1:");
        domain.push_str(&did_id.to_string());

        Ok(domain)
    }
}

#[async_trait]
impl DidMethod for DidWebVh {
    async fn create(
        &self,
        id: Option<DidId>,
        params: &Option<serde_json::Value>,
        keys: Option<DidKeys>,
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
                ));
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

        let external_hosting_url = params
            .as_ref()
            .filter(|params| params.as_object().is_some_and(|obj| !obj.is_empty()))
            .map(|params| {
                DidCreateParams::deserialize(params)
                    .map(|p| p.external_hosting_url)
                    .map_err(|err| DidMethodError::CouldNotCreate(format!("Invalid params: {err}")))
            })
            .transpose()?;

        let domain = self.domain(did_id, external_hosting_url)?;
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
            self.params.resolve_to_insecure_http,
            &self.params,
        )
        .await
    }

    async fn deactivate(
        &self,
        _id: DidId,
        keys: DidKeys,
        log: Option<String>,
    ) -> Result<DidUpdate, DidMethodError> {
        let Some(key_provider) = self.key_provider.as_ref() else {
            return Err(DidMethodError::CouldNotCreate(
                "Missing key provider for did:webvh creation".to_string(),
            ));
        };
        let Some(ref update_keys) = keys.update_keys else {
            return Err(DidMethodError::CouldNotCreate(
                "missing update keys".to_string(),
            ));
        };
        let Some(update_key) = update_keys.first() else {
            return Err(DidMethodError::CouldNotCreate(
                "empty update keys".to_string(),
            ));
        };
        let Some(log) = log else {
            return Err(DidMethodError::CouldNotDeactivate(
                "missing log".to_string(),
            ));
        };
        let Some(last_line) = log.lines().last() else {
            return Err(DidMethodError::CouldNotDeactivate("empty log".to_string()));
        };

        let last_entry: DidLogEntry = serde_json::from_str(last_line).map_err(|err| {
            DidMethodError::CouldNotDeactivate(format!("failed to parse last log entry: {err}"))
        })?;
        let mut new_entry = serialize::DidLogEntry::try_from(last_entry)?;

        let now = now_utc();
        new_entry.version_time = now;
        new_entry.parameters.deactivated = Some(true);
        new_entry.parameters.update_keys = Some(vec![]);
        new_entry.proof = vec![]; // clear proof, otherwise the entry hash will be wrong
        let entry_hash = canonicalize_multihash_encode(&new_entry)?;
        let next_index = log.lines().count() + 1;
        update_version(&mut new_entry, next_index, &entry_hash);

        let key_ref = make_keyref(update_key, key_provider.as_ref())?;
        new_entry.proof = vec![build_proof(&new_entry, &key_ref, now).await?];

        let line = serde_json::to_string(&new_entry).map_err(|err| {
            DidMethodError::CouldNotDeactivate(format!("Failed serializing log line: {err}"))
        })?;
        Ok(DidUpdate {
            deactivated: Some(true),
            log: Some(format!("{log}\n{line}")),
        })
    }

    fn can_be_deactivated(&self) -> bool {
        true
    }

    fn get_capabilities(&self) -> DidCapabilities {
        DidCapabilities {
            operations: vec![Operation::CREATE, Operation::RESOLVE, Operation::DEACTIVATE],
            key_algorithms: vec![KeyAlgorithmType::Ecdsa],
            method_names: vec!["tdw".to_string()],
            features: vec![Feature::SupportsExternalHosting],
            supported_update_key_types: vec![KeyAlgorithmType::Eddsa],
        }
    }

    fn validate_keys(&self, keys: AmountOfKeys) -> bool {
        self.params.keys.validate_keys(keys)
    }

    fn get_keys(&self) -> Option<Keys> {
        Some(self.params.keys.clone())
    }
}
