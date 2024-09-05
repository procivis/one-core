use crate::config::core_config::FormatConfig;
use crate::config::ConfigValidationError;

pub fn validate_format(value: &str, config: &FormatConfig) -> Result<(), ConfigValidationError> {
    config.get_if_enabled(value)?;
    Ok(())
}
