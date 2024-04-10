use crate::model::credential_schema::CredentialSchema;
use crate::provider::credential_formatter::json_ld;
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
        "JSON_LD_CLASSIC" => Ok("ldp_vc".to_string()),
        "JSON_LD_BBSPLUS" => Ok("ldp_vc".to_string()),
        "JSON_LD" => Ok("ldp_vc".to_string()),
        "MDOC" => Ok("mso_mdoc".to_string()),
        _ => Err(FormatError::MappingError(
            "Credential format is invalid!".to_string(),
        )),
    }
}

pub fn map_from_oidc_format_to_core(format: &str) -> Result<String, ServiceError> {
    match format {
        "jwt_vc_json" => Ok("JWT".to_string()),
        "vc+sd-jwt" => Ok("SDJWT".to_string()),
        "ldp_vc" => Ok("JSON_LD".to_string()),
        "mso_mdoc" => Ok("MDOC".to_string()),
        _ => Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::UnsupportedCredentialFormat,
        )),
    }
}

pub fn map_from_oidc_format_to_core_real(
    format: &str,
    token: &str,
) -> Result<String, ServiceError> {
    match format {
        "jwt_vc_json" => Ok("JWT".to_string()),
        "vc+sd-jwt" => Ok("SDJWT".to_string()),
        "ldp_vc" => match json_ld::get_crypto_suite(token) {
            Some(suite) => match suite.as_str() {
                "bbs-2023" => Ok("JSON_LD_BBSPLUS".to_string()),
                _ => Ok("JSON_LD_CLASSIC".to_string()),
            },
            None => Err(ServiceError::OpenID4VCError(
                OpenID4VCIError::UnsupportedCredentialFormat,
            )),
        },
        _ => Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::UnsupportedCredentialFormat,
        )),
    }
}

pub fn map_from_oidc_vp_format_to_core(format: &str) -> Result<String, ServiceError> {
    match format {
        "jwt_vp_json" => Ok("JWT".to_string()),
        "ldp_vp" => Ok("JSON_LD_CLASSIC".to_string()),
        _ => Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::UnsupportedCredentialFormat,
        )),
    }
}

pub fn detect_correct_format(
    credential_schema: &CredentialSchema,
    credential_content: &str,
) -> Result<String, ServiceError> {
    let format = if credential_schema.format.eq("JSON_LD") {
        map_from_oidc_format_to_core_real("ldp_vc", credential_content)
            .map_err(|_| ServiceError::Other("Credential format not resolved".to_owned()))?
    } else {
        credential_schema.format.to_owned()
    };
    Ok(format)
}
