use std::collections::HashMap;

use one_core::service::config::dto::ConfigDTO;
use one_dto_mapper::From;

use super::OneCore;
use crate::error::BindingError;

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Returns the system configuration.
    #[uniffi::method]
    pub async fn get_config(&self) -> Result<ConfigBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let config = core.config_service.get_config()?;
        Ok(config.into())
    }
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ConfigDTO)]
#[uniffi(name = "Config")]
pub struct ConfigBindingDTO {
    /// Credential formats.
    #[from(with_fn = serialize_config_entity)]
    pub format: HashMap<String, String>,
    /// Protocols used for issuance.
    #[from(with_fn = serialize_config_entity)]
    pub issuance_protocol: HashMap<String, String>,
    /// Protocols used for presentation and verification.
    #[from(with_fn = serialize_config_entity)]
    pub verification_protocol: HashMap<String, String>,
    /// Protocols used for communicating.
    #[from(with_fn = serialize_config_entity)]
    pub transport: HashMap<String, String>,
    /// Methods for managing credential status.
    #[from(with_fn = serialize_config_entity)]
    pub revocation: HashMap<String, String>,
    /// DID methods for identifying agents.
    #[from(with_fn = serialize_config_entity)]
    pub did: HashMap<String, String>,
    /// Identifier types for representing agent's identities.
    #[from(with_fn = serialize_config_entity)]
    pub identifier: HashMap<String, String>,
    /// Data types for validation.
    #[from(with_fn = serialize_config_entity)]
    pub datatype: HashMap<String, String>,
    /// Key algorithms used for signatures.
    #[from(with_fn = serialize_config_entity)]
    pub key_algorithm: HashMap<String, String>,
    /// Storage options for keys.
    #[from(with_fn = serialize_config_entity)]
    pub key_storage: HashMap<String, String>,
    /// Trust management solutions.
    #[from(with_fn = serialize_config_entity)]
    pub trust_management: HashMap<String, String>,
    /// Entities held in temporary storage.
    #[from(with_fn = serialize_config_entity)]
    pub cache_entities: HashMap<String, String>,
    /// Tasks which can be run via the `runTask` method.
    #[from(with_fn = serialize_config_entity)]
    pub task: HashMap<String, String>,
    /// Configuration for wallet-initiated issuance flows.
    #[from(with_fn = serialize_config_entity)]
    pub credential_issuer: HashMap<String, String>,
    /// Configurations from the Wallet Provider, including version
    /// management, trust collections, and feature flags.
    #[from(with_fn = serialize_config_entity)]
    pub wallet_provider: HashMap<String, String>,
}

fn serialize_config_entity(input: HashMap<String, serde_json::Value>) -> HashMap<String, String> {
    input
        .into_iter()
        .map(|(key, value)| (key, value.to_string()))
        .collect()
}
