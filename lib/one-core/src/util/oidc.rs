use std::collections::HashMap;

use thiserror::Error;

use crate::provider::credential_formatter::json_ld;
use crate::provider::exchange_protocol::openid4vc::error::{OpenID4VCError, OpenID4VCIError};

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

pub fn create_core_to_oicd_format_map() -> HashMap<String, String> {
    [
        ("JWT", "jwt_vc_json"),
        ("SDJWT", "vc+sd-jwt"),
        ("JSON_LD_CLASSIC", "ldp_vc"),
        ("JSON_LD_BBSPLUS", "ldp_vc"),
        ("JSON_LD", "ldp_vc"),
        ("MDOC", "mso_mdoc"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect()
}

pub fn create_core_to_oicd_presentation_format_map() -> HashMap<String, String> {
    [
        ("jwt_vp_json", "JWT"),
        ("ldp_vp", "JSON_LD_CLASSIC"),
        ("mso_mdoc", "MDOC"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect()
}

pub fn create_oicd_to_core_format_map() -> HashMap<String, String> {
    [
        ("jwt_vc_json", "JWT"),
        ("vc+sd-jwt", "SDJWT"),
        ("ldp_vc", "JSON_LD"),
        ("mso_mdoc", "MDOC"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect()
}

pub fn map_from_oidc_format_to_core(format: &str) -> Result<String, OpenID4VCError> {
    match format {
        "jwt_vc_json" => Ok("JWT".to_string()),
        "vc+sd-jwt" => Ok("SDJWT".to_string()),
        "ldp_vc" => Ok("JSON_LD".to_string()),
        "mso_mdoc" => Ok("MDOC".to_string()),
        _ => Err(OpenID4VCError::OpenID4VCI(
            OpenID4VCIError::UnsupportedCredentialFormat,
        )),
    }
}

pub fn map_from_oidc_format_to_core_detailed(
    format: &str,
    token: Option<&str>,
) -> Result<String, OpenID4VCError> {
    match format {
        "jwt_vc_json" => Ok("JWT".to_string()),
        "vc+sd-jwt" => Ok("SDJWT".to_string()),
        "ldp_vc" => {
            if let Some(token) = token {
                match json_ld::get_crypto_suite(token) {
                    Some(suite) => match suite.as_str() {
                        "bbs-2023" => Ok("JSON_LD_BBSPLUS".to_string()),
                        _ => Ok("JSON_LD_CLASSIC".to_string()),
                    },
                    None => Err(OpenID4VCError::OpenID4VCI(
                        OpenID4VCIError::UnsupportedCredentialFormat,
                    )),
                }
            } else {
                Ok("JSON_LD_CLASSIC".to_string())
            }
        }
        "jwt_vp_json" => Ok("JWT".to_string()),
        "ldp_vp" => Ok("JSON_LD_CLASSIC".to_string()),
        "mso_mdoc" => Ok("MDOC".to_string()),
        _ => Err(OpenID4VCError::OpenID4VCI(
            OpenID4VCIError::UnsupportedCredentialFormat,
        )),
    }
}

// This detects precise format checking e.g. crypto suite
pub fn detect_format_with_crypto_suite(
    credential_schema_format: &str,
    credential_content: &str,
) -> Result<String, OpenID4VCError> {
    let format = if credential_schema_format.starts_with("JSON_LD") {
        map_from_oidc_format_to_core_detailed("ldp_vc", Some(credential_content)).map_err(|_| {
            OpenID4VCError::MappingError("Credential format not resolved".to_owned())
        })?
    } else {
        credential_schema_format.to_owned()
    };
    Ok(format)
}
