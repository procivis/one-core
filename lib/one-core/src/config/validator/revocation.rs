use crate::config::core_config::RevocationConfig;
use crate::config::ConfigValidationError;

pub fn validate_revocation(
    value: &str,
    config: &RevocationConfig,
) -> Result<(), ConfigValidationError> {
    config.get_if_enabled(value)?;
    Ok(())
}
