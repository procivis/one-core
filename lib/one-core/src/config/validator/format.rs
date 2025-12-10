use shared_types::CredentialFormat;

use crate::config::ConfigValidationError;
use crate::config::core_config::{ConfigExt, FormatConfig};

pub fn validate_format(
    value: &CredentialFormat,
    config: &FormatConfig,
) -> Result<(), ConfigValidationError> {
    config.get_if_enabled(value)?;
    Ok(())
}
