use crate::config::{
    core_config::{CoreConfig, ExchangeType},
    ConfigValidationError,
};

pub(super) fn validate_config_entity_presence(
    config: &CoreConfig,
) -> Result<(), ConfigValidationError> {
    if !config
        .exchange
        .as_inner()
        .iter()
        .any(|(_, v)| v.r#type == ExchangeType::ProcivisTemporary)
    {
        Err(ConfigValidationError::KeyNotFound(
            "No exchange method with type PROCIVIS_TEMPORARY".to_string(),
        ))
    } else {
        Ok(())
    }
}
