use std::fmt::Display;
use std::sync::Arc;

use shared_types::KeyStorageId;

use super::{KeySecurityLevel, KeySecurityLevelCapabilities};
use crate::config::core_config::KeySecurityLevelType;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::provider_directory::WithDisabledDecorator;

impl WithDisabledDecorator for dyn KeySecurityLevel {
    fn decorate(self: Arc<dyn KeySecurityLevel>) -> Arc<dyn KeySecurityLevel> {
        Arc::new(DisabledProvider::new(self))
    }
}

impl<T: KeySecurityLevel + Display + ?Sized> KeySecurityLevel for DisabledProvider<T> {
    fn get_capabilities(&self) -> KeySecurityLevelCapabilities {
        self.inner().get_capabilities()
    }
    fn get_priority(&self) -> u64 {
        self.inner().get_priority()
    }
    fn get_key_storages(&self) -> &[KeyStorageId] {
        self.inner().get_key_storages()
    }
    fn level(&self) -> KeySecurityLevelType {
        self.inner().level()
    }
}
