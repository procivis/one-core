use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;

use self::basic::Basic;
use self::dto::KeySecurityLevelCapabilities;
use self::enhanced_basic::EnhancedBasic;
use self::high::High;
use self::moderate::Moderate;
use crate::config::ConfigValidationError;
use crate::config::core_config::{KeySecurityLevelConfig, KeySecurityLevelType};
use crate::provider::key_security_level::mapper::holder_params_from_fields;
use crate::provider::key_storage::provider::KeyProvider;

pub mod basic;
pub mod dto;
pub mod enhanced_basic;
pub mod high;
mod mapper;
pub mod moderate;
pub mod provider;

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

    for (name, fields) in config.iter() {
        let holder_params = holder_params_from_fields(fields).map_err(|err| {
            ConfigValidationError::FieldsDeserialization {
                key: name.to_string(),
                source: err,
            }
        })?;

        for storage_type in &holder_params.key_storages {
            if key_provider.get_key_storage(storage_type).is_none() {
                return Err(ConfigValidationError::EntryNotFound(format!(
                    "No key storage with type {}",
                    storage_type
                )));
            }
        }

        let key_algorithm: Arc<dyn KeySecurityLevel> = match name {
            KeySecurityLevelType::Basic => Arc::new(Basic::new(holder_params)),
            KeySecurityLevelType::EnhancedBasic => Arc::new(EnhancedBasic::new(holder_params)),
            KeySecurityLevelType::Moderate => Arc::new(Moderate::new(holder_params)),
            KeySecurityLevelType::High => Arc::new(High::new(holder_params)),
        };
        levels.insert(*name, key_algorithm);
    }

    for (key, value) in config.iter_mut() {
        if let Some(entity) = levels.get(key) {
            value.capabilities = Some(json!(entity.get_capabilities()));
        }
    }

    Ok(levels)
}
