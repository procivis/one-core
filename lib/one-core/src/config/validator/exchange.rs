use crate::config::core_config::ExchangeConfig;
use crate::service::error::ValidationError;

pub fn validate_exchange_type(value: &str, config: &ExchangeConfig) -> Result<(), ValidationError> {
    config
        .get_if_enabled(value)
        .map(|_| ())
        .map_err(|err| ValidationError::InvalidExchangeType {
            value: value.into(),
            source: err.into(),
        })
}
