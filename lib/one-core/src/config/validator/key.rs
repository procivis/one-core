use std::collections::HashMap;

use crate::config::{data_structure::FormatEntity, validator::ConfigValidationError};

pub fn validate_key(
    value: &str,
    formats: &HashMap<String, FormatEntity>,
) -> Result<(), ConfigValidationError> {
    formats
        .get(value)
        .map(|_| ())
        .ok_or(ConfigValidationError::KeyNotFound(value.to_string()))
}
