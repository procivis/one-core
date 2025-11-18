use crate::config::core_config::KeySecurityLevelType;
use crate::provider::issuance_protocol::model::KeyStorageSecurityLevel;

impl From<KeyStorageSecurityLevel> for KeySecurityLevelType {
    fn from(value: KeyStorageSecurityLevel) -> Self {
        match value {
            KeyStorageSecurityLevel::High => KeySecurityLevelType::High,
            KeyStorageSecurityLevel::Moderate => KeySecurityLevelType::Moderate,
            KeyStorageSecurityLevel::EnhancedBasic => KeySecurityLevelType::EnhancedBasic,
            KeyStorageSecurityLevel::Basic => KeySecurityLevelType::Basic,
        }
    }
}
