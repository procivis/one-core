use one_providers::key_algorithm::error::KeyAlgorithmError;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use time::Duration;

use crate::config::core_config::CoreConfig;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};
use crate::service::key::dto::{KeyGenerateCSRRequestDTO, KeyRequestDTO};

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

pub(super) fn validate_generate_csr_request(
    request: &KeyGenerateCSRRequestDTO,
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

    const MAXIMUM_DAYS: i64 = 457;
    let difference = request.expires_at - request.not_before;

    if difference >= Duration::days(MAXIMUM_DAYS) {
        return Err(ValidationError::CertificateRequestedForMoreThan457Days.into());
    }

    Ok(())
}
