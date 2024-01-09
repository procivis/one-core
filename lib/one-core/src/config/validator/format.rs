use crate::config::{
    core_config::FormatConfig, validator::throw_if_disabled, ConfigValidationError,
};

pub fn validate_format(value: &str, config: &FormatConfig) -> Result<(), ConfigValidationError> {
    let fields = config.get_fields(value)?;
    throw_if_disabled(value, Ok(fields))
}
