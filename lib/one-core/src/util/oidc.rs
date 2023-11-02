use crate::service::error::ServiceError;
use crate::service::oidc::dto::OpenID4VCIError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("Mapping error: `{0}`")]
    MappingError(String),
}

pub fn map_core_to_oidc_format(format: &str) -> Result<String, FormatError> {
    match format {
        "JWT" => Ok("jwt_vc_json".to_string()),
        "SDJWT" => Ok("vc+sd-jwt".to_string()),
        _ => Err(FormatError::MappingError(
            "Credential format invalid!".to_string(),
        )),
    }
}

pub fn map_from_oidc_format_to_core(format: &str) -> Result<String, ServiceError> {
    match format {
        "jwt_vc_json" => Ok("JWT".to_string()),
        "vc+sd-jwt" => Ok("SDJWT".to_string()),
        _ => Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::UnsupportedCredentialFormat,
        )),
    }
}
