use std::collections::HashMap;

use one_core::service::config::dto::ConfigDTO;
use one_dto_mapper::From;

use super::OneCoreBinding;
use crate::error::BindingError;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn get_config(&self) -> Result<ConfigBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let config = core.config_service.get_config()?;
        Ok(config.into())
    }
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ConfigDTO)]
pub struct ConfigBindingDTO {
    #[from(with_fn = serialize_config_entity)]
    pub format: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub issuance_protocol: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub verification_protocol: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub transport: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub revocation: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub did: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub identifier: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub datatype: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub key_algorithm: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub holder_key_storage: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub key_storage: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub trust_management: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub cache_entities: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub task: HashMap<String, String>,
    #[from(with_fn = serialize_config_entity)]
    pub credential_issuer: HashMap<String, String>,
}

fn serialize_config_entity(input: HashMap<String, serde_json::Value>) -> HashMap<String, String> {
    input
        .into_iter()
        .map(|(key, value)| (key, value.to_string()))
        .collect()
}
