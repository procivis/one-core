use std::collections::HashMap;

use crate::config::{data_structure::RevocationEntity, validator::ConfigValidationError};

pub fn validate_revocation(
    value: &str,
    revocation_methods: &HashMap<String, RevocationEntity>,
) -> Result<(), ConfigValidationError> {
    revocation_methods
        .get(value)
        .map(|_| ())
        .ok_or(ConfigValidationError::KeyNotFound(value.to_string()))
}
