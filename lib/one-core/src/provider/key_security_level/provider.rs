use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;

use itertools::Itertools;
use serde_json::json;

use super::KeySecurityLevel;
use super::basic::Basic;
use super::enhanced_basic::EnhancedBasic;
use super::high::High;
use super::mapper::params_from_fields;
use super::moderate::Moderate;
use crate::config::ConfigValidationError;
use crate::config::core_config::{ConfigFields, CoreConfig, KeySecurityLevelType};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub(crate) trait KeySecurityLevelProvider: Send + Sync {
    fn get_from_type(&self, level_type: KeySecurityLevelType) -> Option<Arc<dyn KeySecurityLevel>>;
    fn ordered_by_priority(&self) -> Vec<(KeySecurityLevelType, Arc<dyn KeySecurityLevel>)>;
}

struct KeySecurityLevelProviderImpl {
    levels: HashMap<KeySecurityLevelType, Arc<dyn KeySecurityLevel>>,
}

impl KeySecurityLevelProvider for KeySecurityLevelProviderImpl {
    fn get_from_type(&self, level_type: KeySecurityLevelType) -> Option<Arc<dyn KeySecurityLevel>> {
        self.levels.get(&level_type).cloned()
    }

    fn ordered_by_priority(&self) -> Vec<(KeySecurityLevelType, Arc<dyn KeySecurityLevel>)> {
        self.levels
            .iter()
            .sorted_by_key(|(_, v)| Reverse(v.get_priority()))
            .map(|(k, v)| (*k, v.to_owned()))
            .collect()
    }
}

pub(crate) fn key_security_level_provider_from_config(
    config: &mut CoreConfig,
) -> Result<Arc<dyn KeySecurityLevelProvider>, ConfigValidationError> {
    let mut levels: HashMap<KeySecurityLevelType, Arc<dyn KeySecurityLevel>> = HashMap::new();

    for (name, fields) in config.key_security_level.iter_mut() {
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
            if config.key_storage.get::<(), _>(storage_type).is_ok() {
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

    Ok(Arc::new(KeySecurityLevelProviderImpl { levels }))
}
