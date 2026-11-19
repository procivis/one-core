use shared_types::{CredentialFormat, SerializedCredential};

use crate::config::core_config::FormatType;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::sdjwt::{SdJwtType, detect_sdjwt_type_from_token};
use crate::provider::issuance_protocol::error::{OpenID4VCIError, OpenIDIssuanceError};
use crate::service::error::ServiceError;

// This detects precise format checking e.g. crypto suite
pub(crate) fn detect_format_with_crypto_suite(
    credential_schema_format: &CredentialFormat,
    credential_content: &SerializedCredential,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<CredentialFormat, ServiceError> {
    let format = if credential_schema_format.as_ref().starts_with("JSON_LD") {
        let format_type = map_from_oidc_format_to_core_detailed(
            "ldp_vc",
            Some(&credential_content.as_ref().into()),
        )
        .map_err(|_| ServiceError::MappingError("Credential format not resolved".to_owned()))?;
        let (name, _) = formatter_provider
            .get_formatter_by_type(format_type)
            .ok_or(ServiceError::MappingError(format!(
                "No formatter for type {format_type}"
            )))?;
        name
    } else {
        credential_schema_format.to_owned()
    };
    Ok(format)
}

pub(crate) fn map_to_openid4vp_format(format_type: &FormatType) -> &'static str {
    match format_type {
        FormatType::Jwt => "jwt_vc_json",
        FormatType::SdJwt => "vc+sd-jwt",
        FormatType::SdJwtVc => "vc+sd-jwt",
        FormatType::JsonLdClassic => "ldp_vc",
        FormatType::JsonLdBbsPlus => "ldp_vc",
        FormatType::Mdoc => "mso_mdoc",
    }
}

pub(crate) fn map_from_oidc_format_to_core_detailed(
    format: &str,
    token: Option<&String>,
) -> Result<FormatType, OpenIDIssuanceError> {
    match format {
        "jwt_vc_json" => Ok(FormatType::Jwt),
        "vc+sd-jwt" | "dc+sd-jwt" | "vc sd-jwt" => {
            if let Some(token) = token {
                match detect_sdjwt_type_from_token(&token.as_str().into()).map_err(|_| {
                    OpenIDIssuanceError::OpenID4VCI(OpenID4VCIError::UnsupportedCredentialFormat)
                })? {
                    SdJwtType::SdJwt => Ok(FormatType::SdJwt),
                    SdJwtType::SdJwtVc => Ok(FormatType::SdJwtVc),
                }
            } else {
                Ok(FormatType::SdJwt)
            }
        }
        "ldp_vc" => {
            if let Some(token) = token {
                match get_crypto_suite(token) {
                    Some(suite) => match suite.as_str() {
                        "bbs-2023" => Ok(FormatType::JsonLdBbsPlus),
                        _ => Ok(FormatType::JsonLdClassic),
                    },
                    None => Err(OpenIDIssuanceError::OpenID4VCI(
                        OpenID4VCIError::UnsupportedCredentialFormat,
                    )),
                }
            } else {
                Ok(FormatType::JsonLdClassic)
            }
        }
        "mso_mdoc" => Ok(FormatType::Mdoc),
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
