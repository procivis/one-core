use std::env;

use crate::provider::os_provider::dto::OSName;

pub mod dto;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait OSInfoProvider: Send + Sync {
    async fn get_os_name(&self) -> OSName;
}

pub struct OSInfoProviderImpl;

#[async_trait::async_trait]
impl OSInfoProvider for OSInfoProviderImpl {
    async fn get_os_name(&self) -> OSName {
        match env::consts::OS {
            "ios" => OSName::Ios,
            "android" => OSName::Android,
            _ => OSName::Web,
        }
    }
}
