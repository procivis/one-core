use crate::mapper::oidc::map_from_oidc_format_to_core_detailed;
use crate::model::proof::Proof;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::service::error::ServiceError;

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
pub(crate) fn determine_response_mode_openid4vp_draft(
    proof: &Proof,
) -> Result<String, VerificationProtocolError> {
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
