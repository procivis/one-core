use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, IssuanceProtocolType, VerificationProtocolType};

pub(super) fn validate_issuance_protocol_type(
    expected_exchange_type: IssuanceProtocolType,
    config: &CoreConfig,
    exchange: &str,
) -> Result<(), ConfigValidationError> {
    let exchange_type = config.issuance_protocol.get_fields(exchange)?.r#type;

    if exchange_type != expected_exchange_type {
        Err(ConfigValidationError::InvalidType(
            expected_exchange_type.to_string(),
            exchange.to_string(),
        ))
    } else {
        Ok(())
    }
}

pub(super) fn validate_verification_protocol_type(
    expected_exchange_type: VerificationProtocolType,
    config: &CoreConfig,
    exchange: &str,
) -> Result<(), ConfigValidationError> {
    let exchange_type = config.verification_protocol.get_fields(exchange)?.r#type;

    if exchange_type != expected_exchange_type {
        Err(ConfigValidationError::InvalidType(
            expected_exchange_type.to_string(),
            exchange.to_string(),
        ))
    } else {
        Ok(())
    }
}
