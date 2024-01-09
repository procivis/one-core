use crate::{
    config::{core_config::ExchangeConfig, validator::throw_if_disabled},
    service::error::ValidationError,
};

pub fn validate_exchange_type(value: &str, config: &ExchangeConfig) -> Result<(), ValidationError> {
    let fields = config
        .get_fields(value)
        .map_err(|err| ValidationError::InvalidExchangeType {
            value: value.into(),
            source: err.into(),
        })?;

    throw_if_disabled(value, Ok(fields)).map_err(|error| ValidationError::InvalidExchangeType {
        value: value.into(),
        source: error.into(),
    })
}
