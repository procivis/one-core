use std::collections::HashMap;

use crate::config::{data_structure::ExchangeEntity, validator::ConfigValidationError};

pub fn validate_exchange_type(
    value: &str,
    exchange: &HashMap<String, ExchangeEntity>,
) -> Result<(), ConfigValidationError> {
    exchange
        .get(value)
        .map(|_| ())
        .ok_or(ConfigValidationError::KeyNotFound(value.to_string()))
}
