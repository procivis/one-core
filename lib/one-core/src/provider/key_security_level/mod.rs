use std::fmt::{Display, Formatter};

use proc_macros::provider_mock;
use shared_types::KeyStorageId;

use self::dto::KeySecurityLevelCapabilities;
use crate::config::core_config::KeySecurityLevelType;
use crate::provider::Provider;

pub mod basic;
mod decorators;
pub mod dto;
pub mod enhanced_basic;
pub mod high;
mod mapper;
pub mod moderate;
pub mod provider;

#[provider_mock]
pub trait KeySecurityLevel: Provider + Send + Sync {
    fn get_capabilities(&self) -> KeySecurityLevelCapabilities;
    fn get_priority(&self) -> u64;
    fn get_key_storages(&self) -> &[KeyStorageId];

    fn level(&self) -> KeySecurityLevelType;
}

impl Display for dyn KeySecurityLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key security level `{}`", self.level())
    }
}
