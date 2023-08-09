use std::collections::HashMap;

use crate::config::data_structure::ConfigEntity;
use crate::config::ConfigParseError;

fn validate_type<T>(entity: &ConfigEntity<String, T>, types: &[String]) -> bool {
    let matching_type = types
        .iter()
        .find(|entity_type| entity.r#type == **entity_type);
    matching_type.is_some()
}

pub fn validate_types<T>(
    entity: &HashMap<String, ConfigEntity<String, T>>,
    types: &[String],
) -> Result<(), ConfigParseError> {
    let result = entity.iter().find(|(_, v)| !validate_type(v, types));
    match result {
        None => Ok(()),
        Some((key, value)) => Err(ConfigParseError::InvalidType(
            key.to_owned(),
            value.r#type.to_owned(),
        )),
    }
}
