use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;

use self::basic::Basic;
use self::dto::KeySecurityLevelCapabilities;
use self::enhanced_basic::EnhancedBasic;
use self::high::High;
use self::moderate::Moderate;
use crate::config::ConfigValidationError;
use crate::config::core_config::{ConfigFields, KeySecurityLevelConfig, KeySecurityLevelType};
use crate::provider::key_security_level::mapper::params_from_fields;
use crate::provider::key_storage::provider::KeyProvider;

pub mod basic;
pub mod dto;
pub mod enhanced_basic;
pub mod high;
mod mapper;
pub mod moderate;
pub mod provider;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait KeySecurityLevel: Send + Sync {
    fn get_capabilities(&self) -> KeySecurityLevelCapabilities;
    fn get_priority(&self) -> u64;
    fn get_key_storages(&self) -> &[String];
}

pub(crate) fn key_security_levels_from_config(
    config: &mut KeySecurityLevelConfig,
    key_provider: Arc<dyn KeyProvider>,
) -> Result<HashMap<KeySecurityLevelType, Arc<dyn KeySecurityLevel>>, ConfigValidationError> {
    let mut levels: HashMap<KeySecurityLevelType, Arc<dyn KeySecurityLevel>> = HashMap::new();

    for (name, fields) in config.iter_mut() {
        if !fields.enabled() {
            continue;
        }
        let params = params_from_fields(fields).map_err(|err| {
            ConfigValidationError::FieldsDeserialization {
                key: name.to_string(),
                source: err,
            }
        })?;

        for storage_type in &params.holder.key_storages {
            if key_provider.get_key_storage(storage_type).is_none() {
                return Err(ConfigValidationError::EntryNotFound(format!(
                    "No key storage with type {}",
                    storage_type
                )));
            }
        }

        let security_level: Arc<dyn KeySecurityLevel> = match name {
            KeySecurityLevelType::Basic => Arc::new(Basic::new(params)),
            KeySecurityLevelType::EnhancedBasic => Arc::new(EnhancedBasic::new(params)),
            KeySecurityLevelType::Moderate => Arc::new(Moderate::new(params)),
            KeySecurityLevelType::High => Arc::new(High::new(params)),
        };
        fields.capabilities = Some(json!(security_level.get_capabilities()));
        levels.insert(*name, security_level);
    }
    Ok(levels)
}
