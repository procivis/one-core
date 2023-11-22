use crate::config::{core_config::FormatConfig, ConfigValidationError};

pub fn validate_format(value: &str, config: &FormatConfig) -> Result<(), ConfigValidationError> {
    _ = config.get_fields(value)?;

    Ok(())
}
