use crate::config::core_config::FormatType;
use crate::provider::credential_formatter::sdjwt::{SdJwtType, detect_sdjwt_type_from_token};
use crate::provider::issuance_protocol::error::{OpenID4VCIError, OpenIDIssuanceError};

pub(crate) fn map_to_openid4vp_format(
    format_type: &FormatType,
) -> Result<&'static str, OpenID4VCIError> {
    match format_type {
        FormatType::Jwt => Ok("jwt_vc_json"),
        FormatType::SdJwt => Ok("vc+sd-jwt"),
        FormatType::SdJwtVc => Ok("vc+sd-jwt"),
        FormatType::JsonLdClassic => Ok("ldp_vc"),
        FormatType::JsonLdBbsPlus => Ok("ldp_vc"),
        FormatType::Mdoc => Ok("mso_mdoc"),
        FormatType::PhysicalCard => Err(OpenID4VCIError::UnsupportedCredentialFormat),
    }
}

pub(crate) fn map_from_openid4vp_format(format: &str) -> Result<String, OpenID4VCIError> {
    match format {
        "jwt_vc_json" => Ok(FormatType::Jwt.to_string()),
        "jwt_vp_json" => Ok(FormatType::Jwt.to_string()),
        "dc+sd-jwt" => Ok(FormatType::SdJwt.to_string()),
        "vc+sd-jwt" => Ok(FormatType::SdJwt.to_string()),
        "ldp_vc" => Ok("JSON_LD".to_string()),
        "ldp_vp" => Ok("JSON_LD".to_string()),
        "mso_mdoc" => Ok(FormatType::Mdoc.to_string()),
        _ => Err(OpenID4VCIError::UnsupportedCredentialFormat),
    }
}

pub(crate) fn map_from_oidc_format_to_core_detailed(
    format: &str,
    token: Option<&str>,
) -> Result<String, OpenIDIssuanceError> {
    match format {
        "jwt_vc_json" => Ok(FormatType::Jwt.to_string()),
        "vc+sd-jwt" | "dc+sd-jwt" | "vc sd-jwt" => {
            if let Some(token) = token {
                match detect_sdjwt_type_from_token(token).map_err(|_| {
                    OpenIDIssuanceError::OpenID4VCI(OpenID4VCIError::UnsupportedCredentialFormat)
                })? {
                    SdJwtType::SdJwt => Ok("SD_JWT".to_string()),
                    SdJwtType::SdJwtVc => Ok("SD_JWT_VC".to_string()),
                }
            } else {
                Ok(FormatType::SdJwt.to_string())
            }
        }
        "ldp_vc" => {
            if let Some(token) = token {
                match get_crypto_suite(token) {
                    Some(suite) => match suite.as_str() {
                        "bbs-2023" => Ok("JSON_LD_BBSPLUS".to_string()),
                        _ => Ok("JSON_LD_CLASSIC".to_string()),
                    },
                    None => Err(OpenIDIssuanceError::OpenID4VCI(
                        OpenID4VCIError::UnsupportedCredentialFormat,
                    )),
                }
            } else {
                Ok(FormatType::JsonLdClassic.to_string())
            }
        }
        "jwt_vp_json" => Ok(FormatType::Jwt.to_string()),
        "ldp_vp" => Ok(FormatType::JsonLdClassic.to_string()),
        "mso_mdoc" => Ok(FormatType::Mdoc.to_string()),
        _ => Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::UnsupportedCredentialFormat,
        )),
    }
}

fn get_crypto_suite(json_ld_str: &str) -> Option<String> {
    match serde_json::from_str::<serde_json::Value>(json_ld_str) {
        Ok(json_ld) => json_ld.get("proof").and_then(|proof| {
            proof
                .get("cryptosuite")
                .and_then(|cryptosuite| cryptosuite.as_str().map(|s| s.to_string()))
        }),
        Err(_) => None,
    }
}
