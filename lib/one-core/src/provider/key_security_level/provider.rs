use std::collections::HashMap;
use std::sync::Arc;

use crate::config::core_config::KeySecurityLevelType;
use crate::provider::key_security_level::KeySecurityLevel;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub(crate) trait KeySecurityLevelProvider: Send + Sync {
    fn get_from_type(&self, level_type: KeySecurityLevelType) -> Option<Arc<dyn KeySecurityLevel>>;
}

pub(crate) struct KeySecurityLevelProviderImpl {
    levels: HashMap<KeySecurityLevelType, Arc<dyn KeySecurityLevel>>,
}

impl KeySecurityLevelProviderImpl {
    pub(crate) fn new(levels: HashMap<KeySecurityLevelType, Arc<dyn KeySecurityLevel>>) -> Self {
        Self { levels }
    }
}

impl KeySecurityLevelProvider for KeySecurityLevelProviderImpl {
    fn get_from_type(&self, level_type: KeySecurityLevelType) -> Option<Arc<dyn KeySecurityLevel>> {
        self.levels.get(&level_type).cloned()
    }
}
