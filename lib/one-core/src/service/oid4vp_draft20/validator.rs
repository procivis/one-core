use crate::config::core_config::{CoreConfig, VerificationProtocolType};
use crate::config::ConfigValidationError;

pub(super) fn validate_config_entity_presence(
    config: &CoreConfig,
) -> Result<(), ConfigValidationError> {
    if !config
        .verification_protocol
        .iter()
        .any(|(_, v)| v.r#type == VerificationProtocolType::OpenId4VpDraft20)
    {
        Err(ConfigValidationError::EntryNotFound(
            "No exchange method with type OPENID4VC".to_string(),
        ))
    } else {
        Ok(())
    }
}
