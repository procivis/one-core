use crate::config::core_config::CoreConfig;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};
use crate::service::key::dto::KeyRequestDTO;

pub(super) fn validate_generate_request(
    request: &KeyRequestDTO,
    config: &CoreConfig,
) -> Result<(), ValidationError> {
    config
        .key_algorithm
        .get_if_enabled(&request.key_type)
        .map_err(|err| ValidationError::InvalidKeyAlgorithm(err.to_string()))?;
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
        .get_key_algorithm(key_type)
        .ok_or(KeyAlgorithmError::NotSupported(key_type.to_owned()))?;
    if !key_algorithm
        .get_capabilities()
        .features
        .contains(&"GENERATE_CSR".to_string())
    {
        return Err(BusinessLogicError::UnsupportedKeyTypeForCSR.into());
    }
    Ok(())
}
