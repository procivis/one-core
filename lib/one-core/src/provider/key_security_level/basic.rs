use proc_macros::Provider;
use standardized_types::openid4vci::SecurityLevel;

use super::KeySecurityLevel;
use super::dto::{KeySecurityLevelCapabilities, Params};
use crate::config::core_config::KeySecurityLevelType;

#[derive(Provider)]
pub struct Basic {
    params: Params,
}

impl KeySecurityLevel for Basic {
    fn get_capabilities(&self) -> KeySecurityLevelCapabilities {
        KeySecurityLevelCapabilities {
            openid_security_level: vec![SecurityLevel::Basic],
        }
    }

    fn get_priority(&self) -> u64 {
        self.params.holder.priority
    }

    fn get_key_storages(&self) -> &[String] {
        self.params.holder.key_storages.as_slice()
    }

    fn level(&self) -> KeySecurityLevelType {
        KeySecurityLevelType::Basic
    }
}

impl Basic {
    pub(crate) fn new(params: Params) -> Self {
        Self { params }
    }
}
