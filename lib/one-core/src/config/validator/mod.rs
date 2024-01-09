use super::{core_config::Fields, ConfigValidationError};

pub mod datatype;
pub mod did;
pub mod exchange;
pub mod format;
pub mod key;
pub mod revocation;

fn throw_if_disabled<T>(
    value: &str,
    fields: Result<&Fields<T>, ConfigValidationError>,
) -> Result<(), ConfigValidationError> {
    if let Ok(fields) = fields {
        if fields.disabled.is_some_and(|value| value) {
            return Err(ConfigValidationError::KeyDisabled(value.to_string()));
        }
    }
    Ok(())
}
