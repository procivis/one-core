use std::str::FromStr;

use crate::config::core_config::{ConfigExt, CoreConfig, KeyAlgorithmType};
use crate::service::key::error::KeyServiceError;

pub(super) fn validate_generate_request(
    key_type: &str,
    storage_type: &str,
    config: &CoreConfig,
) -> Result<(), KeyServiceError> {
    let key_type = KeyAlgorithmType::from_str(key_type)
        .map_err(|err| KeyServiceError::InvalidKeyAlgorithm(err.to_string()))?;
    let algorithm_config = config
        .key_algorithm
        .get(&key_type)
        .ok_or(KeyServiceError::InvalidKeyAlgorithm(key_type.to_string()))?;
    if !algorithm_config.enabled {
        return Err(KeyServiceError::InvalidKeyAlgorithm(
            "algorithm is disabled".to_string(),
        ));
    }

    config
        .key_storage
        .get_if_enabled(storage_type)
        .map_err(|err| KeyServiceError::InvalidKeyStorage(err.to_string()))?;
    Ok(())
}
