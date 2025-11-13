use crate::model::wallet_unit_attestation::KeyStorageSecurityLevel;
use crate::provider::key_security_level::KeySecurityLevel;
use crate::provider::key_security_level::dto::{HolderParams, KeySecurityLevelCapabilities};

pub struct EnhancedBasic {
    holder_params: HolderParams,
}

impl KeySecurityLevel for EnhancedBasic {
    fn get_capabilities(&self) -> KeySecurityLevelCapabilities {
        KeySecurityLevelCapabilities {
            openid_security_level: vec![KeyStorageSecurityLevel::EnhancedBasic],
        }
    }
    fn get_priority(&self) -> u64 {
        self.holder_params.priority
    }

    fn get_key_storages(&self) -> &[String] {
        self.holder_params.key_storages.as_slice()
    }
}

impl EnhancedBasic {
    pub(crate) fn new(holder_params: HolderParams) -> Self {
        Self { holder_params }
    }
}
