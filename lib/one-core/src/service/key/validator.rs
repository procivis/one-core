use std::str::FromStr;

use crate::config::core_config::{CoreConfig, KeyAlgorithmType};
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::model::Features;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};
use crate::service::key::dto::KeyRequestDTO;

pub(super) fn validate_generate_request(
    request: &KeyRequestDTO,
    config: &CoreConfig,
) -> Result<(), ValidationError> {
    let key_type = KeyAlgorithmType::from_str(&request.key_type)
        .map_err(|err| ValidationError::InvalidKeyAlgorithm(err.to_string()))?;
    let algorithm_config =
        config
            .key_algorithm
            .get(&key_type)
            .ok_or(ValidationError::InvalidKeyAlgorithm(
                request.key_type.clone(),
            ))?;
    if algorithm_config.disabled.is_some_and(|value| value) {
        return Err(ValidationError::InvalidKeyAlgorithm(
            "algorithm is disabled".to_string(),
        ));
    }

    config
        .key_storage
        .get_if_enabled(&request.storage_type)
        .map_err(|err| ValidationError::InvalidKeyStorage(err.to_string()))?;
    Ok(())
}

pub(super) fn validate_key_algorithm_for_csr(
    key_type: &str,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<(), ServiceError> {
    let key_algorithm = &key_algorithm_provider
        .key_algorithm_from_name(key_type)
        .ok_or(KeyAlgorithmError::NotSupported(key_type.to_owned()))?;
    if !key_algorithm
        .get_capabilities()
        .features
        .contains(&Features::GenerateCSR)
    {
        return Err(BusinessLogicError::UnsupportedKeyTypeForCSR.into());
    }
    Ok(())
}
