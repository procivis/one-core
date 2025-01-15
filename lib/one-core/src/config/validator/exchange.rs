use crate::config::core_config::ExchangeConfig;
use crate::provider::exchange_protocol::dto::{ExchangeProtocolCapabilities, Operation};
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

pub fn validate_exchange_operation(
    exchange_capabilities: &ExchangeProtocolCapabilities,
    operation: &Operation,
) -> Result<(), ValidationError> {
    if !exchange_capabilities.operations.contains(operation) {
        return Err(ValidationError::InvalidExchangeOperation);
    }
    Ok(())
}
