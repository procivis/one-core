use crate::config::{core_config::TrustManagementConfig, ConfigValidationError};

pub fn validate_trust_management(
    value: &str,
    config: &TrustManagementConfig,
) -> Result<(), ConfigValidationError> {
    config.get_if_enabled(value)?;
    Ok(())
}
