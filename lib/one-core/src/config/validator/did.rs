use crate::config::ConfigValidationError;
use crate::config::core_config::{ConfigExt, DidConfig};

pub fn validate_did_method(value: &str, config: &DidConfig) -> Result<(), ConfigValidationError> {
    config.get_if_enabled(value)?;
    Ok(())
}
