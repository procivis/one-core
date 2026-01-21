use shared_types::RevocationMethodId;

use crate::config::ConfigValidationError;
use crate::config::core_config::{ConfigExt, RevocationConfig};

pub fn validate_revocation(
    value: &RevocationMethodId,
    config: &RevocationConfig,
) -> Result<(), ConfigValidationError> {
    config.get_if_enabled(value)?;
    Ok(())
}
