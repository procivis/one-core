use std::cmp::Reverse;

use one_dto_mapper::convert_inner;

use crate::config::core_config::KeySecurityLevelType;
use crate::model::credential_schema::KeyStorageSecurity;
use crate::provider::issuance_protocol::model::KeyStorageSecurityLevel;
use crate::provider::key_security_level::provider::KeySecurityLevelProvider;
use crate::service::error::ValidationError;

pub(crate) fn match_key_security_level(
    key_storage: &str,
    issuer_accepted_levels: &[KeyStorageSecurityLevel],
    key_security_level_provider: &dyn KeySecurityLevelProvider,
) -> Result<KeyStorageSecurityLevel, ValidationError> {
    let mut security_levels = issuer_accepted_levels
        .iter()
        .filter_map(|level| {
            key_security_level_provider.get_from_type(KeySecurityLevelType::from(*level))
        })
        .collect::<Vec<_>>();
    security_levels.sort_by_key(|p| Reverse(p.get_priority()));
    security_levels
        .iter()
        .filter(|provider| {
            provider
                .get_key_storages()
                .contains(&key_storage.to_string())
        })
        .filter_map(|provider| {
            provider
                .get_capabilities()
                .openid_security_level
                .first()
                .copied()
        })
        .next()
        .ok_or(ValidationError::UnfulfilledKeyStorageSecurityLevel {
            key_storage: key_storage.to_string(),
            required_security_levels: convert_inner(issuer_accepted_levels.to_vec()),
        })
}

pub(crate) fn validate_key_storage_supports_security_requirement(
    key_storage: &str,
    key_storage_security: &Option<KeyStorageSecurity>,
    key_security_level_provider: &dyn KeySecurityLevelProvider,
) -> Result<(), ValidationError> {
    let Some(key_storage_security) = key_storage_security else {
        return Ok(());
    };
    let security_level = key_security_level_provider
        .get_from_type(KeySecurityLevelType::from(*key_storage_security))
        .ok_or(ValidationError::KeyStorageSecurityDisabled(
            *key_storage_security,
        ))?;
    let supported_storages = security_level.get_key_storages();
    if !supported_storages.contains(&key_storage.to_string()) {
        return Err(ValidationError::UnfulfilledKeyStorageSecurityLevel {
            key_storage: key_storage.to_string(),
            required_security_levels: vec![*key_storage_security],
        });
    }
    Ok(())
}
