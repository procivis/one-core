use serde::Deserialize;

use crate::config::{
    core_config::{KeyAlgorithmConfig, KeyStorageConfig},
    ConfigValidationError,
};

pub fn find_key_algorithm(
    value: &str,
    config: &KeyAlgorithmConfig,
) -> Result<String, ConfigValidationError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Params {
        algorithm: String,
    }

    let params: Params = config.get(value)?;

    Ok(params.algorithm)
}

pub fn validate_key_storage(
    value: &str,
    config: &KeyStorageConfig,
) -> Result<(), ConfigValidationError> {
    _ = config.get_fields(value)?;

    Ok(())
}
