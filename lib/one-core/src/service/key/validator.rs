use crate::{
    config::core_config::CoreConfig,
    service::{error::ValidationError, key::dto::KeyRequestDTO},
};

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
