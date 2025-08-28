use crate::service::error::ServiceError;

pub(crate) fn validate_audience(
    audience: &[String],
    expected: Option<&str>,
) -> Result<(), ServiceError> {
    let Some(expected) = expected else {
        return Ok(());
    };

    let contains = audience.iter().any(|s| s.as_str() == expected);
    if !contains {
        return Err(ServiceError::ValidationError(format!(
            "{expected} is not intended audience",
        )));
    }
    Ok(())
}
