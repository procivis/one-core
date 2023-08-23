use std::collections::HashMap;

use crate::config::{data_structure::DidEntity, validator::ConfigValidationError};

pub fn validate_did_method(
    value: &str,
    did_methods: &HashMap<String, DidEntity>,
) -> Result<(), ConfigValidationError> {
    did_methods
        .get(value)
        .map(|_| ())
        .ok_or(ConfigValidationError::KeyNotFound(value.to_string()))
}
