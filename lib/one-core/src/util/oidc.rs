use crate::config::core_config::FormatType;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::json_ld;
use crate::provider::credential_formatter::sdjwt::{SdJwtType, detect_sdjwt_type_from_token};
use crate::provider::issuance_protocol::openid4vci_draft13::error::{
    OpenID4VCIError, OpenIDIssuanceError,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::service::error::ServiceError;

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
                match json_ld::get_crypto_suite(token) {
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

// This detects precise format checking e.g. crypto suite
pub(crate) fn detect_format_with_crypto_suite(
    credential_schema_format: &str,
    credential_content: &str,
) -> Result<String, ServiceError> {
    let format = if credential_schema_format.starts_with("JSON_LD") {
        map_from_oidc_format_to_core_detailed("ldp_vc", Some(credential_content))
            .map_err(|_| ServiceError::MappingError("Credential format not resolved".to_owned()))?
    } else {
        credential_schema_format.to_owned()
    };
    Ok(format)
}

/// Determine the `response_mode` value to set in the authorization request for the given [Proof].
/// Options are:
/// - `direct_post.jwt` for `MDOC` presentations
///     - `MDOC` will only be used for a [Proof] if _all_ credentials presented have the format `MDOC`
/// - `direct_post` for everything else
pub(crate) fn determine_response_mode(proof: &Proof) -> Result<String, VerificationProtocolError> {
    let mut format_iter = proof
        .schema
        .iter()
        .flat_map(|proof_schema| proof_schema.input_schemas.as_ref())
        .flatten()
        .flat_map(|input_schema| input_schema.credential_schema.as_ref())
        .map(|credenial_schema| &credenial_schema.format)
        .peekable();

    if format_iter.peek().is_none() {
        return Err(VerificationProtocolError::Failed(format!(
            "Cannot determine response mode for proof {}",
            proof.id
        )));
    }

    let mdoc_only = format_iter.all(|format| format == "MDOC");

    let response_mode = match mdoc_only {
        true => "direct_post.jwt".to_string(),
        false => "direct_post".to_string(),
    };
    Ok(response_mode)
}
