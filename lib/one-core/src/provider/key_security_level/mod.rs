use self::dto::KeySecurityLevelCapabilities;

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
