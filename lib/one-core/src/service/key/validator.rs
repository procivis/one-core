use crate::{
    config::{
        core_config::CoreConfig,
        validator::key::{validate_key_algorithm, validate_key_storage},
        ConfigValidationError,
    },
    service::key::dto::KeyRequestDTO,
};

pub(super) fn validate_generate_request(
    request: &KeyRequestDTO,
    config: &CoreConfig,
) -> Result<(), ConfigValidationError> {
    validate_key_algorithm(&request.key_type, &config.key_algorithm)?;
    validate_key_storage(&request.storage_type, &config.key_storage)
}
