use super::error::IdentifierServiceError;
use crate::config::core_config::{IdentifierConfig, IdentifierType};

pub(crate) fn validate_identifier_type(
    identifier_type: IdentifierType,
    config: &IdentifierConfig,
) -> Result<(), IdentifierServiceError> {
    config
        .get(&identifier_type)
        .filter(|cfg| cfg.enabled)
        .map(|_| ())
        .ok_or(IdentifierServiceError::IdentifierTypeDisabled(
            identifier_type,
        ))
}
