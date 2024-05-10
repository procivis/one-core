use crate::config::core_config::{KeyAlgorithmConfig, KeyAlgorithmType};
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::service::key::dto::KeyGenerateCSRRequestDTO;
use crate::{
    config::core_config::CoreConfig,
    service::{error::ValidationError, key::dto::KeyRequestDTO},
};
use time::Duration;

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
    config: &KeyAlgorithmConfig,
) -> Result<(), ServiceError> {
    let config_key_type = config.get_fields(key_type)?.r#type;
    if config_key_type != KeyAlgorithmType::Es256 && config_key_type != KeyAlgorithmType::Eddsa {
        return Err(BusinessLogicError::UnsupportedKeyTypeForCSR.into());
    }

    const MAXIMUM_DAYS: i64 = 457;
    let difference = request.expires_at - request.not_before;

    if difference >= Duration::days(MAXIMUM_DAYS) {
        return Err(ValidationError::CertificateRequestedForMoreThan457Days.into());
    }

    Ok(())
}
