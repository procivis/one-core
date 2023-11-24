use crate::config::{core_config::KeyStorageConfig, ConfigValidationError};

pub fn validate_key_storage(
    value: &str,
    config: &KeyStorageConfig,
) -> Result<(), ConfigValidationError> {
    _ = config.get_fields(value)?;

    Ok(())
}
