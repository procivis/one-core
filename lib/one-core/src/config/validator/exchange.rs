use crate::config::core_config::ExchangeConfig;
use crate::provider::exchange_protocol::dto::{ExchangeProtocolCapabilities, Operation};
use crate::service::error::{BusinessLogicError, ValidationError};

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

pub(crate) fn validate_exchange_did_compatibility(
    exchange_capabilities: &ExchangeProtocolCapabilities,
    operation: &Operation,
    did_method: &str,
) -> Result<(), BusinessLogicError> {
    let did_methods = match operation {
        Operation::ISSUANCE => &exchange_capabilities.issuance_did_methods,
        Operation::VERIFICATION => &exchange_capabilities.verification_did_methods,
    };

    let did_method = did_method.to_owned();
    if !did_methods.contains(&did_method) {
        return Err(BusinessLogicError::InvalidDidMethod { method: did_method });
    }
    Ok(())
}
