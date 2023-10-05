use std::collections::HashMap;

use crate::config::{
    data_structure::{FormatEntity, KeyAlgorithmEntity, KeyStorageEntity},
    validator::ConfigValidationError,
};

pub fn find_key_algorithm<'a>(
    value: &str,
    algorithms: &'a HashMap<String, KeyAlgorithmEntity>,
) -> Result<&'a KeyAlgorithmEntity, ConfigValidationError> {
    algorithms
        .get(value)
        .ok_or(ConfigValidationError::UnknownType(value.to_string()))
}

pub fn validate_key(
    value: &str,
    formats: &HashMap<String, FormatEntity>,
) -> Result<(), ConfigValidationError> {
    formats
        .get(value)
        .map(|_| ())
        .ok_or(ConfigValidationError::KeyNotFound(value.to_string()))
}

pub fn validate_key_algorithm(
    value: &str,
    algorithms: &HashMap<String, KeyAlgorithmEntity>,
) -> Result<(), ConfigValidationError> {
    algorithms
        .get(value)
        .map(|_| ())
        .ok_or(ConfigValidationError::UnknownType(value.to_string()))
}

pub fn validate_key_storage(
    value: &str,
    storage: &HashMap<String, KeyStorageEntity>,
) -> Result<(), ConfigValidationError> {
    storage
        .get(value)
        .map(|_| ())
        .ok_or(ConfigValidationError::UnknownType(value.to_string()))
}
