use crate::config::core_config::{CoreConfig, ExchangeType};
use crate::config::ConfigValidationError;

pub(super) fn validate_config_entity_presence(
    config: &CoreConfig,
) -> Result<(), ConfigValidationError> {
    if !config
        .exchange
        .iter()
        .any(|(_, v)| v.r#type == ExchangeType::ProcivisTemporary)
    {
        Err(ConfigValidationError::KeyNotFound(
            "No exchange method with type PROCIVIS_TEMPORARY".to_string(),
        ))
    } else {
        Ok(())
    }
}

pub(super) fn validate_exchange_type(
    expected_exchange_type: ExchangeType,
    config: &CoreConfig,
    exchange: &str,
) -> Result<(), ConfigValidationError> {
    let exchange_type = config.exchange.get_fields(exchange)?.r#type;

    if exchange_type != expected_exchange_type {
        Err(ConfigValidationError::InvalidType(
            expected_exchange_type.to_string(),
            exchange.to_string(),
        ))
    } else {
        Ok(())
    }
}
