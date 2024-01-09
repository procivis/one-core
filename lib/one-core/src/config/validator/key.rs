use crate::config::{
    core_config::{KeyAlgorithmConfig, KeyStorageConfig},
    validator::throw_if_disabled,
    ConfigValidationError,
};

pub fn validate_key_algorithm(
    value: &str,
    config: &KeyAlgorithmConfig,
) -> Result<(), ConfigValidationError> {
    throw_if_disabled(value, config.get_fields(value))
}

pub fn validate_key_storage(
    value: &str,
    config: &KeyStorageConfig,
) -> Result<(), ConfigValidationError> {
    throw_if_disabled(value, config.get_fields(value))
}
