use std::cmp::Reverse;
use std::sync::Arc;

use itertools::Itertools;

use super::KeySecurityLevel;
use super::basic::Basic;
use super::enhanced_basic::EnhancedBasic;
use super::high::High;
use super::mapper::params_from_fields;
use super::moderate::Moderate;
use crate::config::ConfigValidationError;
use crate::config::core_config::{
    CoreConfig, KeySecurityLevelFields, KeySecurityLevelType, KeyStorageConfig,
};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt, NestedError};
use crate::provider::provider_directory::{InitializationError, ProviderDirectory};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub(crate) trait KeySecurityLevelProvider: Send + Sync {
    fn get_from_type(
        &self,
        level_type: KeySecurityLevelType,
    ) -> Result<Arc<dyn KeySecurityLevel>, NestedError>;
    fn ordered_by_priority(&self) -> Vec<(KeySecurityLevelType, Arc<dyn KeySecurityLevel>)>;
}

impl KeySecurityLevelProvider
    for ProviderDirectory<KeySecurityLevelType, KeySecurityLevelFields, dyn KeySecurityLevel>
{
    fn get_from_type(
        &self,
        level_type: KeySecurityLevelType,
    ) -> Result<Arc<dyn KeySecurityLevel>, NestedError> {
        self.provider(&level_type)
    }

    fn ordered_by_priority(&self) -> Vec<(KeySecurityLevelType, Arc<dyn KeySecurityLevel>)> {
        self.iter()
            .sorted_by_key(|(_, v)| Reverse(v.get_priority()))
            .map(|(k, v)| (*k, v.to_owned()))
            .collect()
    }
}

pub(crate) fn key_security_level_provider_from_config(
    config: &mut CoreConfig,
) -> Result<Arc<dyn KeySecurityLevelProvider>, ConfigValidationError> {
    let initializer = |level: &KeySecurityLevelType, field: &KeySecurityLevelFields| {
        initialize_provider(level, field, &config.key_storage)
    };
    let directory =
        ProviderDirectory::initialize(config.key_security_level.iter_mut(), initializer)
            .error_while("initializing key security level providers")?;
    Ok(Arc::new(directory))
}

fn initialize_provider(
    level: &KeySecurityLevelType,
    fields: &KeySecurityLevelFields,
    key_storage_config: &KeyStorageConfig,
) -> Result<Arc<dyn KeySecurityLevel>, InitializationError> {
    let params = params_from_fields(fields).map_err(|err| InitializationError::InvalidParams {
        key: level.to_string(),
        source: err,
    })?;

    for storage_type in &params.holder.key_storages {
        if key_storage_config.get::<(), _>(storage_type).is_ok() {
            return Err(ConfigValidationError::EntryNotFound(format!(
                "No key storage with type {storage_type}",
            ))
            .error_while(format!("initializing key security level: {level}"))
            .into());
        }
    }

    let security_level: Arc<dyn KeySecurityLevel> = match level {
        KeySecurityLevelType::Basic => Arc::new(Basic::new(params)),
        KeySecurityLevelType::EnhancedBasic => Arc::new(EnhancedBasic::new(params)),
        KeySecurityLevelType::Moderate => Arc::new(Moderate::new(params)),
        KeySecurityLevelType::High => Arc::new(High::new(params)),
    };

    Ok(security_level)
}
