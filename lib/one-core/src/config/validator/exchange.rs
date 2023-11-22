use crate::config::{core_config::ExchangeConfig, ConfigValidationError};

pub fn validate_exchange_type(
    value: &str,
    config: &ExchangeConfig,
) -> Result<(), ConfigValidationError> {
    _ = config.get_fields(value)?;

    Ok(())
}
