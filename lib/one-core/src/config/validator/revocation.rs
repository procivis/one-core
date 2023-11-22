use crate::config::{core_config::RevocationConfig, ConfigValidationError};

pub fn validate_revocation(
    value: &str,
    config: &RevocationConfig,
) -> Result<(), ConfigValidationError> {
    _ = config.get_fields(value)?;

    Ok(())
}
