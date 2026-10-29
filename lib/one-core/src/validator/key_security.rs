use std::cmp::Reverse;

use one_dto_mapper::convert_inner;
use standardized_types::openid4vci::SecurityLevel;

use crate::config::core_config::KeySecurityLevelType;
use crate::provider::key_security_level::provider::KeySecurityLevelProvider;
use crate::service::error::ValidationError;

pub(crate) fn match_key_security_level(
    key_storage: &str,
    issuer_accepted_levels: &[SecurityLevel],
    key_security_level_provider: &dyn KeySecurityLevelProvider,
) -> Result<SecurityLevel, ValidationError> {
    let mut security_levels = issuer_accepted_levels
        .iter()
        .filter_map(|level| {
            key_security_level_provider
                .get_from_type(KeySecurityLevelType::from(*level))
                .ok()
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
