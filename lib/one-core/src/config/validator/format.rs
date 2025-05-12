use crate::config::ConfigValidationError;
use crate::config::core_config::FormatConfig;

pub fn validate_format(value: &str, config: &FormatConfig) -> Result<(), ConfigValidationError> {
    config.get_if_enabled(value)?;
    Ok(())
}
