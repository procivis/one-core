use std::collections::HashMap;
use std::ops::{Add, Sub};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

use super::model::PresentationSubmissionDescriptorDTO;
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::DidType;
use crate::model::proof_schema::ProofInputSchema;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::MobileSecurityObject;
use crate::provider::credential_formatter::mdoc_formatter::try_extracting_mso_from_token;
use crate::provider::credential_formatter::model::{
    DetailCredential, ExtractPresentationCtx, HolderBindingCtx, Presentation, TokenVerifier,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::revocation::lvvc::util::is_lvvc_credential;
use crate::provider::revocation::model::{
    CredentialDataByRole, CredentialRevocationState, VerifierCredentialData,
};
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::mapper::vec_last_position_from_token_path;
use crate::provider::verification_protocol::openid4vp::model::ValidatedProofClaimDTO;
use crate::util::key_verification::KeyVerification;
use crate::util::oidc::map_from_oidc_format_to_core_detailed;

pub(super) async fn peek_presentation(
    presentation_string: &str,
    oidc_format: &str,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
) -> Result<Presentation, OpenID4VCError> {
    let format = map_from_oidc_format_to_core_detailed(oidc_format, Some(presentation_string))
        .map_err(|_| OpenID4VCError::VCFormatsNotSupported)?;
    let formatter = formatter_provider
        .get_formatter(&format)
        .ok_or(OpenID4VCError::VCFormatsNotSupported)?;

    let presentation = formatter
        .extract_presentation_unverified(presentation_string, ExtractPresentationCtx::default())
        .await
        .map_err(|e| {
            if matches!(e, FormatterError::CouldNotExtractPresentation(_)) {
                OpenID4VCError::VPFormatsNotSupported
            } else {
                OpenID4VCError::Other(e.to_string())
            }
        })?;

    Ok(presentation)
}

pub(super) async fn validate_presentation(
    presentation_string: &str,
    nonce: &str,
    oidc_format: &str,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    key_verification: Box<dyn TokenVerifier>,
    context: ExtractPresentationCtx,
) -> Result<Presentation, OpenID4VCError> {
    let format = map_from_oidc_format_to_core_detailed(oidc_format, Some(presentation_string))
        .map_err(|_| OpenID4VCError::VCFormatsNotSupported)?;
    let formatter = formatter_provider
        .get_formatter(&format)
        .ok_or(OpenID4VCError::VCFormatsNotSupported)?;

    let presentation = formatter
        .extract_presentation(presentation_string, key_verification, context)
        .await
        .map_err(|e| {
            if matches!(e, FormatterError::CouldNotExtractPresentation(_)) {
                OpenID4VCError::VPFormatsNotSupported
            } else {
                OpenID4VCError::Other(e.to_string())
            }
        })?;

    validate_issuance_time(&presentation.issued_at, formatter.get_leeway())?;
    validate_expiration_time(&presentation.expires_at, formatter.get_leeway())?;

    if presentation
        .nonce
        .as_ref()
        .is_none_or(|presentation_nonce| presentation_nonce != nonce)
    {
        return Err(OpenID4VCError::ValidationError(
            "Nonce not matched".to_string(),
        ));
    }

    Ok(presentation)
}

fn is_revocation_credential(credential: &DetailCredential) -> bool {
    is_lvvc_credential(credential)
        || (credential.claims.claims.contains_key("encodedList")
            && credential.claims.claims.contains_key("statusPurpose"))
}

pub(super) fn validate_against_redirect_uris(
    redirect_uris: &[String],
    uri: Option<&str>,
) -> Result<(), VerificationProtocolError> {
    if redirect_uris.is_empty() {
        return Ok(());
    }

    if let Some(uri) = uri {
        if !redirect_uris.iter().any(|v| v == uri) {
            return Err(VerificationProtocolError::Failed(
                "redirect_uri or response_uri is not allowed by verifier_attestation token"
                    .to_string(),
            ));
        }
    }

    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn validate_credential(
    presentation: Presentation,
    presentation_submitted: &PresentationSubmissionDescriptorDTO,
    extracted_lvvcs: &[DetailCredential],
    proof_schema_input: &ProofInputSchema,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    key_verification: Box<KeyVerification>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    revocation_method_provider: &Arc<dyn RevocationMethodProvider>,
    holder_binding_ctx: HolderBindingCtx,
) -> Result<(DetailCredential, Option<MobileSecurityObject>), OpenID4VCError> {
    let holder_did = presentation
        .issuer_did
        .as_ref()
        .ok_or(OpenID4VCError::ValidationError(
            "Presentation missing holder id".to_string(),
        ))?;

    let credential_index = presentation_submitted
        .path_nested
        .as_ref()
        .map(|p| vec_last_position_from_token_path(&p.path))
        .transpose()?
        .unwrap_or(0);

    let credential_token =
        presentation
            .credentials
            .get(credential_index)
            .ok_or(OpenID4VCError::ValidationError(format!(
                "Credential at index {credential_index} not found",
            )))?;

    let format = proof_schema_input
        .credential_schema
        .as_ref()
        .map(|schema| schema.format.as_str())
        .ok_or(OpenID4VCError::VCFormatsNotSupported)?;
    let formatter = formatter_provider
        .get_formatter(format)
        .ok_or(OpenID4VCError::VCFormatsNotSupported)?;

    let credential = formatter
        .extract_credentials(
            credential_token,
            proof_schema_input.credential_schema.as_ref(),
            key_verification,
            Some(holder_binding_ctx),
        )
        .await
        .map_err(|e| {
            if matches!(e, FormatterError::CouldNotExtractCredentials(_)) {
                OpenID4VCError::VCFormatsNotSupported
            } else {
                OpenID4VCError::Other(e.to_string())
            }
        })?;

    validate_issuance_time(&credential.valid_from, formatter.get_leeway())?;
    validate_expiration_time(&credential.valid_until, formatter.get_leeway())?;

    if is_revocation_credential(&credential) {
        return Ok((credential, None));
    };

    for credential_status in credential.status.iter() {
        let (revocation_method, _) = revocation_method_provider
            .get_revocation_method_by_status_type(&credential_status.r#type)
            .ok_or(OpenID4VCError::MissingRevocationProviderForType(
                credential_status.r#type.clone(),
            ))?;

        match revocation_method
            .check_credential_revocation_status(
                credential_status,
                &credential.issuer,
                Some(CredentialDataByRole::Verifier(Box::new(
                    VerifierCredentialData {
                        credential: credential.to_owned(),
                        extracted_lvvcs: extracted_lvvcs.to_owned(),
                        proof_input: proof_schema_input.to_owned(),
                    },
                ))),
                false,
            )
            .await?
        {
            CredentialRevocationState::Valid => {}
            CredentialRevocationState::Revoked | CredentialRevocationState::Suspended { .. } => {
                return Err(OpenID4VCError::CredentialIsRevokedOrSuspended);
            }
        }
    }

    // Check if all subjects of the submitted VCs is matching the holder did.
    let claim_subject = match &credential.subject {
        None => {
            return Err(OpenID4VCError::ValidationError(
                "Claim Holder DID missing".to_owned(),
            ));
        }
        Some(did) => did,
    };

    let claim_subject_did_document = did_method_provider
        .resolve(claim_subject)
        .await
        .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

    let holder_did_document = did_method_provider
        .resolve(holder_did)
        .await
        .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

    // Simplest case, the DIDs (and resolved documents) are exactly the same
    let same_did_document = claim_subject_did_document == holder_did_document;

    // If did documents / DIDs are different, validate that holder has matching key in claim subject
    if !same_did_document {
        let did_method =
            DidType::from_str(holder_did.method().to_uppercase().as_str()).map_err(|_| {
                OpenID4VCError::ValidationError(format!(
                    "Unsupported holder DID method: {}",
                    holder_did.method()
                ))
            })?;
        if formatter
            .get_capabilities()
            .holder_did_methods
            .contains(&did_method)
        {
            // Get the holder's verification key
            let holder_key = holder_did_document
                .find_verification_method(None, None)
                .ok_or(OpenID4VCError::ValidationError(
                    "Presentation signer DID document contains no verification methods".to_owned(),
                ))?;

            // Find matching key in claim subject's verification methods
            claim_subject_did_document
                .verification_method
                .iter()
                .find(|vm| vm.public_key_jwk == holder_key.public_key_jwk)
                .ok_or(OpenID4VCError::ValidationError(
                    "Presentation signer key not found in claim subject DID document".to_owned(),
                ))?;
        } else {
            // We restrict this key matching logic to DID methods with one verification method
            return Err(OpenID4VCError::ValidationError(format!(
                "Unsupported holder DID method: {}",
                holder_did.method()
            )));
        }
    }

    let mut mso = None;
    if format == "MDOC" {
        mso = Some(
            try_extracting_mso_from_token(credential_token)
                .await
                .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?,
        );
    }

    Ok((credential, mso))
}

pub(crate) fn validate_issuance_time(
    issued_at: &Option<OffsetDateTime>,
    leeway: u64,
) -> Result<(), OpenID4VCError> {
    if issued_at.is_none() {
        return Ok(());
    }

    let now = OffsetDateTime::now_utc();
    let issued = issued_at.ok_or(OpenID4VCError::ValidationError(
        "Missing issuance date".to_owned(),
    ))?;

    if issued > now.add(Duration::from_secs(leeway)) {
        return Err(OpenID4VCError::ValidationError(
            "Issued in future".to_owned(),
        ));
    }

    Ok(())
}

pub(crate) fn validate_expiration_time(
    expires_at: &Option<OffsetDateTime>,
    leeway: u64,
) -> Result<(), OpenID4VCError> {
    if expires_at.is_none() {
        return Ok(());
    }

    let now = OffsetDateTime::now_utc();
    let expires = expires_at.ok_or(OpenID4VCError::ValidationError(
        "Missing expiration date".to_owned(),
    ))?;

    if expires < now.sub(Duration::from_secs(leeway)) {
        return Err(OpenID4VCError::ValidationError("Expired".to_owned()));
    }

    Ok(())
}

pub(super) fn validate_claims(
    received_credential: DetailCredential,
    proof_input_schema: &ProofInputSchema,
    mso: Option<MobileSecurityObject>,
) -> Result<Vec<ValidatedProofClaimDTO>, OpenID4VCError> {
    let expected_credential_claims =
        proof_input_schema
            .claim_schemas
            .as_ref()
            .ok_or(OpenID4VCError::MappingError(
                "Missing claim schemas".to_string(),
            ))?;

    let credential_schema =
        proof_input_schema
            .credential_schema
            .as_ref()
            .ok_or(OpenID4VCError::MappingError(
                "Missing credential schema".to_string(),
            ))?;
    let mut proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();

    for expected_credential_claim in expected_credential_claims {
        let resolved = resolve_claim(
            &expected_credential_claim.schema.key,
            &received_credential.claims.claims,
        );
        if let Some(value) = resolved? {
            // Expected claim present in the presentation
            proved_claims.push(ValidatedProofClaimDTO {
                proof_input_claim: expected_credential_claim.to_owned(),
                credential: received_credential.to_owned(),
                value: value.to_owned(),
                credential_schema: credential_schema.to_owned(),
                mdoc_mso: mso.clone(),
            })
        } else if expected_credential_claim.required {
            // Fail as required claim was not sent
            return Err(OpenID4VCError::ValidationError(
                "Required claim not submitted".to_string(),
            ));
        } else {
            // Not present but also not required
            continue;
        }
    }
    Ok(proved_claims)
}

fn resolve_claim<'a>(
    claim_name: &str,
    claims: &'a HashMap<String, serde_json::Value>,
) -> Result<Option<&'a serde_json::Value>, OpenID4VCError> {
    // Simplest case - claim is not nested
    if let Some(value) = claims.get(claim_name) {
        return Ok(Some(value));
    }

    match claim_name.split_once(NESTED_CLAIM_MARKER) {
        None => Ok(None),
        Some((prefix, rest)) => match claims.get(prefix) {
            None => Ok(None),
            Some(value) => resolve_claim_inner(rest, value),
        },
    }
}

fn resolve_claim_inner<'a>(
    claim_name: &str,
    claims: &'a serde_json::Value,
) -> Result<Option<&'a serde_json::Value>, OpenID4VCError> {
    if let Some(value) = claims.get(claim_name) {
        return Ok(Some(value));
    }

    match claim_name.split_once(NESTED_CLAIM_MARKER) {
        Some((prefix, rest)) => match claims.get(prefix) {
            None => Ok(None),
            Some(value) => resolve_claim_inner(rest, value),
        },
        None => Ok(None),
    }
}
