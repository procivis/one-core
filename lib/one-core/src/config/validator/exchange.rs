use crate::config::core_config::ExchangeConfig;
use crate::service::error::ValidationError;

pub fn validate_exchange_type(
    exchange: &str,
    config: &ExchangeConfig,
) -> Result<(), ValidationError> {
    config.get_if_enabled(exchange).map(|_| ()).map_err(|err| {
        ValidationError::InvalidExchangeType {
            value: exchange.into(),
            source: err.into(),
        }
    })
}
