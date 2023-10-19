use crate::service::error::ServiceError;

pub fn get_did_method_id(did_method: &str) -> Result<String, ServiceError> {
    Ok(match did_method {
        "key" => "KEY".to_string(),
        _ => {
            return Err(ServiceError::ValidationError(format!(
                "Did method '{did_method}' not supported"
            )));
        }
    })
}
