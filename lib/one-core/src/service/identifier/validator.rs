use crate::config::core_config::{IdentifierConfig, IdentifierType};
use crate::service::error::ValidationError;

pub(crate) fn validate_identifier_type(
    identifier_type: &IdentifierType,
    config: &IdentifierConfig,
) -> Result<(), ValidationError> {
    config
        .get(identifier_type)
        .filter(|cfg| cfg.enabled.unwrap_or_default())
        .map(|_| ())
        .ok_or(ValidationError::IdentifierTypeDisabled(
            identifier_type.to_string(),
        ))
}
