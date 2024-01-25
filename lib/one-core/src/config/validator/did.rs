use crate::config::{core_config::DidConfig, ConfigValidationError};

pub fn validate_did_method(value: &str, config: &DidConfig) -> Result<(), ConfigValidationError> {
    config.get_if_enabled(value)?;
    Ok(())
}
