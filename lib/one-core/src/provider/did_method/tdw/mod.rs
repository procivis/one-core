//! Implementation of did:tdw.
//! https://identity.foundation/didwebvh/v0.3/

use std::sync::Arc;

use async_trait::async_trait;
use create::{DidDocKeys, UpdateKeys};
use proc_macros::Provider;
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{DidId, DidMethodId, DidValue};
use time::Duration;
use url::Url;

use super::keys::Keys;
use super::model::{DidCapabilities, DidDocument, Feature, Operation};
use super::{DidCreated, DidKeys, DidMethod, DidUpdate};
use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::proto::http_client::HttpClient;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::did_method::tdw::common::{
    build_proof, canonicalize_multihash_encode, make_keyref, now_utc, update_version,
};
use crate::provider::did_method::tdw::deserialize::DidLogEntry;
use crate::provider::did_method::tdw::mapper::url_to_did;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::provider_directory::InitializationError;

mod common;
mod create;
mod resolver;
mod serialize;
mod verification;

mod deserialize;
mod mapper;
#[cfg(test)]
mod test;

#[serde_as]
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Params {
    #[serde(default)]
    pub keys: Keys,
    #[serde(default)]
    pub max_did_log_entry_check: Option<u32>,
    #[serde(default)]
    pub resolve_to_insecure_http: bool,
    #[serde(default)]
    #[serde_as(as = "DurationSeconds<i64>")]
    pub leeway_seconds: Duration,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidCreateParams {
    external_hosting_url: Url,
}

#[derive(Provider)]
pub struct DidTdw {
    config_id: DidMethodId,
    params: Params,
    core_base_url: Option<String>,
    client: Arc<dyn HttpClient>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
}

impl DidTdw {
    pub fn new(
        config_id: DidMethodId,
        params: serde_json::Value,
        core_base_url: Option<String>,
        client: Arc<dyn HttpClient>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
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
            core_base_url,
            client,
            did_method_provider,
            key_provider,
        })
    }

    fn domain(
        &self,
        did_id: DidId,
        external_hosting_url: Option<Url>,
    ) -> Result<String, DidMethodError> {
        if let Some(external_host) = external_hosting_url {
            return url_to_did(external_host);
        }

        let base_url = self.core_base_url.as_ref().ok_or_else(|| {
            DidMethodError::InitializationError("Missing core base url".to_string())
        })?;

        let url = Url::parse(base_url)?;

        let mut domain = url_to_did(url)?;
        domain.push_str(":ssi:did-webvh:v1:");
        domain.push_str(&did_id.to_string());

        Ok(domain)
    }
}

#[async_trait]
impl DidMethod for DidTdw {
    async fn create(
        &self,
        id: DidId,
        params: &Option<serde_json::Value>,
        keys: DidKeys,
    ) -> Result<DidCreated, DidMethodError> {
        let update_keys = match keys.update_keys.as_deref() {
            None | Some([]) => {
                return Err(DidMethodError::CreationError(
                    "Missing update keys for did:tdw".to_string(),
                ));
            }
            Some([active, next @ ..]) => UpdateKeys { active, next },
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
                    .map_err(|err| DidMethodError::CreationError(format!("Invalid params: {err}")))
            })
            .transpose()?;

        let domain = self.domain(id, external_hosting_url)?;
        let (did, log) = create::create(
            &domain,
            did_doc_keys,
            update_keys,
            self.key_provider.as_ref(),
        )
        .await?;

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
        keys: DidKeys,
        log: Option<String>,
    ) -> Result<DidUpdate, DidMethodError> {
        let Some(ref update_keys) = keys.update_keys else {
            return Err(DidMethodError::CouldNotDeactivate(
                "missing update keys".to_string(),
            ));
        };
        let Some(update_key) = update_keys.first() else {
            return Err(DidMethodError::CouldNotDeactivate(
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

        let key_ref = make_keyref(update_key, self.key_provider.as_ref())?;
        new_entry.proof = vec![build_proof(&new_entry, &key_ref, now).await?];

        let line = serde_json::to_string(&new_entry).map_err(|err| {
            DidMethodError::CouldNotDeactivate(format!("Failed serializing log line: {err}"))
        })?;
        Ok(DidUpdate {
            deactivated: Some(true),
            log: Some(format!("{log}\n{line}")),
        })
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

    fn get_keys(&self) -> Option<Keys> {
        Some(self.params.keys.clone())
    }

    fn get_reference_for_key(&self, key: &Key) -> Result<String, DidMethodError> {
        Ok(format!("key-{}", key.id))
    }

    fn config_name(&self) -> &DidMethodId {
        &self.config_id
    }
}
