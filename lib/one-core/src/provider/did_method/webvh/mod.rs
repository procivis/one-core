//! Swiss-profile subset of did:webvh 1.0.
//! https://identity.foundation/didwebvh/v1.0/

use std::sync::Arc;

use async_trait::async_trait;
use proc_macros::Provider;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{DurationSeconds, serde_as, skip_serializing_none};
use shared_types::{DidId, DidMethodId, DidValue};
use time::Duration;

use super::keys::Keys;
use super::model::{DidCapabilities, DidDocument, Feature, Operation};
use super::provider::DidMethodProvider;
use super::{DidCreated, DidKeys, DidMethod, DidUpdate};
use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::proto::http_client::HttpClient;
use crate::provider::credential_formatter::vcdm::VcdmProof;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::provider_directory::InitializationError;

mod common;
mod create;
mod deactivate;
mod identifier;
mod mapper;
mod resolver;
mod verification;

#[cfg(test)]
mod test;

const METHOD: &str = "did:webvh:1.0";
const PREFIX: &str = "did:webvh:";
const SCID_PLACEHOLDER: &str = "{SCID}";
const CRYPTOSUITE: &str = "eddsa-jcs-2022";

#[serde_as]
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Params {
    #[serde(default)]
    keys: Keys,
    #[serde(default)]
    max_did_log_entry_check: Option<u32>,
    #[serde(default)]
    resolve_to_insecure_http: bool,
    /// Include `profile_version` in the DID document state as required by the Swiss Profile Anchor.
    /// https://swiyu-admin-ch.github.io/specifications/swiss-profile-anchor/#did-log-entry-version
    #[serde(default)]
    include_swiss_profile_marker: bool,
    #[serde(default)]
    #[serde_as(as = "DurationSeconds<i64>")]
    leeway_seconds: Duration,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogParameters {
    method: Option<String>,
    scid: Option<String>,
    update_keys: Option<Vec<String>>,
    next_key_hashes: Option<Vec<String>>,
    portable: Option<bool>,
    witness: Option<serde_json::Map<String, Value>>,
    watchers: Option<Vec<String>>,
    deactivated: Option<bool>,
    ttl: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LogEntry {
    version_id: String,
    version_time: String,
    parameters: LogParameters,
    state: Value,
    proof: Vec<VcdmProof>,
}

struct KeyRef {
    multibase: String,
    handle: KeyHandle,
}

#[derive(Debug)]
struct VerifiedLog {
    entries: Vec<LogEntry>,
    active_keys: Vec<String>,
    deactivated: bool,
}

#[derive(Provider)]
pub struct DidWebvh {
    config_id: DidMethodId,
    params: Params,
    core_base_url: Option<String>,
    client: Arc<dyn HttpClient>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl DidWebvh {
    pub fn new(
        config_id: DidMethodId,
        params: Value,
        core_base_url: Option<String>,
        client: Arc<dyn HttpClient>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
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
            key_algorithm_provider,
        })
    }
}

#[async_trait]
impl DidMethod for DidWebvh {
    async fn create(
        &self,
        id: DidId,
        params: &Option<Value>,
        keys: DidKeys,
    ) -> Result<DidCreated, DidMethodError> {
        create::create(self, id, params, keys).await
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodError> {
        resolver::resolve(self, did).await
    }

    async fn deactivate(
        &self,
        _id: DidId,
        keys: DidKeys,
        log: Option<String>,
    ) -> Result<DidUpdate, DidMethodError> {
        deactivate::deactivate(self, keys, log).await
    }

    fn get_capabilities(&self) -> DidCapabilities {
        DidCapabilities {
            operations: vec![Operation::CREATE, Operation::RESOLVE, Operation::DEACTIVATE],
            key_algorithms: vec![
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::BbsPlus,
                KeyAlgorithmType::MlDsa,
            ],
            method_names: vec!["webvh".to_string()],
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
