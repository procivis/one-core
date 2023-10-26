use thiserror::Error;

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("Mapping error: `{0}`")]
    MappingError(String),
}

pub fn map_format_to_oidc_format(format: &str) -> Result<String, FormatError> {
    match format {
        "JWT" => Ok("jwt_vc_json".to_string()),
        "SDJWT" => Ok("vc+sd-jwt".to_string()),
        _ => Err(FormatError::MappingError(
            "Credential format invalid!".to_string(),
        )),
    }
}
