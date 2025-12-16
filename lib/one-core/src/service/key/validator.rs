use std::str::FromStr;

use crate::config::core_config::{ConfigExt, CoreConfig, KeyAlgorithmType};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::key::Key;
use crate::provider::key_algorithm::model::Features;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
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
    if algorithm_config.enabled.is_some_and(|value| !value) {
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

pub(super) fn validate_key_algorithm_for_csr(
    key: &Key,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<(), KeyServiceError> {
    let key_type = KeyAlgorithmType::from_str(&key.key_type).map_err(|_| {
        KeyServiceError::InvalidKeyAlgorithm {
            key_algorithm: key.key_type.to_string(),
        }
    })?;
    let key_algorithm = key_algorithm_provider
        .key_algorithm_from_type(key_type)
        .ok_or(KeyServiceError::MissingKeyAlgorithmProvider { key_type })?;

    if !key_algorithm
        .get_capabilities()
        .features
        .contains(&Features::GenerateCSR)
    {
        return Err(KeyServiceError::UnsupportedKeyTypeForCSR);
    }
    Ok(())
}
