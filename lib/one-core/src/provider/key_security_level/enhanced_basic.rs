use crate::provider::issuance_protocol::model::KeyStorageSecurityLevel;
use crate::provider::key_security_level::KeySecurityLevel;
use crate::provider::key_security_level::dto::{KeySecurityLevelCapabilities, Params};

pub struct EnhancedBasic {
    params: Params,
}

impl KeySecurityLevel for EnhancedBasic {
    fn get_capabilities(&self) -> KeySecurityLevelCapabilities {
        KeySecurityLevelCapabilities {
            openid_security_level: vec![KeyStorageSecurityLevel::EnhancedBasic],
        }
    }
    fn get_priority(&self) -> u64 {
        self.params.holder.priority
    }

    fn get_key_storages(&self) -> &[String] {
        self.params.holder.key_storages.as_slice()
    }
}

impl EnhancedBasic {
    pub(crate) fn new(params: Params) -> Self {
        Self { params }
    }
}
