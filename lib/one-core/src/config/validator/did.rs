use crate::config::{core_config::DidConfig, validator::throw_if_disabled, ConfigValidationError};

pub fn validate_did_method(value: &str, config: &DidConfig) -> Result<(), ConfigValidationError> {
    let fields = config.get_fields(value)?;
    throw_if_disabled(value, Ok(fields))
}
