use std::str::FromStr;

use crate::config::core_config::{ConfigExt, CoreConfig, KeyAlgorithmType};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::service::error::ValidationError;
use crate::service::key::error::KeyServiceError;

pub(super) fn validate_generate_request(
    key_type: &str,
    storage_type: &str,
    config: &CoreConfig,
) -> Result<(), KeyServiceError> {
    let key_type = KeyAlgorithmType::from_str(key_type)
        .map_err(|err| ValidationError::InvalidKeyAlgorithm(err.to_string()))
        .error_while("validating key type")?;
    let algorithm_config = config
        .key_algorithm
        .get(&key_type)
        .ok_or(ValidationError::InvalidKeyAlgorithm(key_type.to_string()))
        .error_while("getting key algorithm config")?;
    if !algorithm_config.enabled {
        return Err(
            ValidationError::InvalidKeyAlgorithm("algorithm is disabled".to_string())
                .error_while("validating key algorithm")
                .into(),
        );
    }

    config
        .key_storage
        .get_if_enabled(storage_type)
        .map_err(|err| ValidationError::InvalidKeyStorage(err.to_string()))
        .error_while("validating key storage")?;
    Ok(())
}
