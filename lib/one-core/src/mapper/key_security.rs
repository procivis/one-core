use standardized_types::openid4vci::SecurityLevel;

use crate::config::core_config::KeySecurityLevelType;
use crate::model::credential_schema::KeyStorageSecurity;

impl From<SecurityLevel> for KeySecurityLevelType {
    fn from(value: SecurityLevel) -> Self {
        match value {
            SecurityLevel::High => KeySecurityLevelType::High,
            SecurityLevel::Moderate => KeySecurityLevelType::Moderate,
            SecurityLevel::EnhancedBasic => KeySecurityLevelType::EnhancedBasic,
            SecurityLevel::Basic => KeySecurityLevelType::Basic,
        }
    }
}

impl From<SecurityLevel> for KeyStorageSecurity {
    fn from(value: SecurityLevel) -> Self {
        match value {
            SecurityLevel::High => KeyStorageSecurity::High,
            SecurityLevel::Moderate => KeyStorageSecurity::Moderate,
            SecurityLevel::EnhancedBasic => KeyStorageSecurity::EnhancedBasic,
            SecurityLevel::Basic => KeyStorageSecurity::Basic,
        }
    }
}

impl From<KeyStorageSecurity> for SecurityLevel {
    fn from(value: KeyStorageSecurity) -> Self {
        match value {
            KeyStorageSecurity::High => SecurityLevel::High,
            KeyStorageSecurity::Moderate => SecurityLevel::Moderate,
            KeyStorageSecurity::EnhancedBasic => SecurityLevel::EnhancedBasic,
            KeyStorageSecurity::Basic => SecurityLevel::Basic,
        }
    }
}
