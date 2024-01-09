use crate::config::{
    core_config::RevocationConfig, validator::throw_if_disabled, ConfigValidationError,
};

pub fn validate_revocation(
    value: &str,
    config: &RevocationConfig,
) -> Result<(), ConfigValidationError> {
    let fields = config.get_fields(value)?;
    throw_if_disabled(value, Ok(fields))
}
