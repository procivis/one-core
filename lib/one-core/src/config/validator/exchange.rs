use crate::{config::core_config::ExchangeConfig, service::error::ValidationError};

pub fn validate_exchange_type(value: &str, config: &ExchangeConfig) -> Result<(), ValidationError> {
    _ = config
        .get_fields(value)
        .map_err(|err| ValidationError::InvalidExchangeType {
            value: value.into(),
            source: err.into(),
        })?;

    Ok(())
}
