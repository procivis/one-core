use std::collections::HashMap;
use std::ops::{Add, Sub};
use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::interaction::Interaction;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::model::proof_schema::ProofInputSchema;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::MobileSecurityObject;
use crate::provider::credential_formatter::mdoc_formatter::try_extracting_mso_from_token;
use crate::provider::credential_formatter::model::{
    DetailCredential, ExtractPresentationCtx, Presentation, TokenVerifier,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::exchange_protocol::openid4vc::error::{OpenID4VCError, OpenID4VCIError};
use crate::provider::exchange_protocol::openid4vc::mapper::vec_last_position_from_token_path;
use crate::provider::exchange_protocol::openid4vc::model::{
    NestedPresentationSubmissionDescriptorDTO, OpenID4VCIInteractionDataDTO,
    OpenID4VCITokenRequestDTO, ValidatedProofClaimDTO,
};
use crate::provider::exchange_protocol::openid4vc::service::FnMapOidcFormatToExternalDetailed;
use crate::provider::revocation::lvvc::util::is_lvvc_credential;
use crate::provider::revocation::model::{
    CredentialDataByRole, CredentialRevocationState, VerifierCredentialData,
};
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::util::key_verification::KeyVerification;

pub fn throw_if_latest_proof_state_not_eq(
    proof: &Proof,
    state: ProofStateEnum,
) -> Result<(), OpenID4VCError> {
    let latest_state = proof
        .state
        .as_ref()
        .ok_or(OpenID4VCError::MappingError("state is None".to_string()))?
        .first()
        .ok_or(OpenID4VCError::MappingError("state is missing".to_string()))?
        .to_owned();

    if latest_state.state != state {
        return Err(OpenID4VCError::InvalidProofState {
            state: latest_state.state,
        });
    }
    Ok(())
}

pub(super) async fn peek_presentation(
    presentation_string: &str,
    oidc_format: &str,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    map_from_oidc_format_to_external: FnMapOidcFormatToExternalDetailed,
) -> Result<Presentation, OpenID4VCError> {
    let format = map_from_oidc_format_to_external(oidc_format, None)?;
    let formatter = formatter_provider
        .get_formatter(&format)
        .ok_or(OpenID4VCIError::VCFormatsNotSupported)?;

    let presentation = formatter
        .extract_presentation_unverified(presentation_string, ExtractPresentationCtx::default())
        .await
        .map_err(|e| {
            if matches!(e, FormatterError::CouldNotExtractPresentation(_)) {
                OpenID4VCIError::VPFormatsNotSupported.into()
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
    map_from_oidc_format_to_external: FnMapOidcFormatToExternalDetailed,
) -> Result<Presentation, OpenID4VCError> {
    let format = map_from_oidc_format_to_external(oidc_format, None)?;
    let formatter = formatter_provider
        .get_formatter(&format)
        .ok_or(OpenID4VCIError::VCFormatsNotSupported)?;

    let presentation = formatter
        .extract_presentation(presentation_string, key_verification, context)
        .await
        .map_err(|e| {
            if matches!(e, FormatterError::CouldNotExtractPresentation(_)) {
                OpenID4VCIError::VPFormatsNotSupported.into()
            } else {
                OpenID4VCError::Other(e.to_string())
            }
        })?;

    validate_issuance_time(&presentation.issued_at, formatter.get_leeway())?;
    validate_expiration_time(&presentation.expires_at, formatter.get_leeway())?;

    if !presentation
        .nonce
        .as_ref()
        .is_some_and(|presentation_nonce| presentation_nonce == nonce)
    {
        return Err(OpenID4VCError::ValidationError(
            "Nonce not matched".to_string(),
        ));
    }

    Ok(presentation)
}

fn is_revocation_credential(credential: &DetailCredential) -> bool {
    is_lvvc_credential(credential)
        || (credential.claims.values.contains_key("encodedList")
            && credential.claims.values.contains_key("statusPurpose"))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn validate_credential(
    presentation: Presentation,
    path_nested: &NestedPresentationSubmissionDescriptorDTO,
    extracted_lvvcs: &[DetailCredential],
    proof_schema_input: &ProofInputSchema,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    key_verification: Box<KeyVerification>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    revocation_method_provider: &Arc<dyn RevocationMethodProvider>,
    map_from_oidc_format_to_external: FnMapOidcFormatToExternalDetailed,
) -> Result<(DetailCredential, Option<MobileSecurityObject>), OpenID4VCError> {
    let holder_did = presentation
        .issuer_did
        .as_ref()
        .ok_or(OpenID4VCError::ValidationError(
            "Missing holder id".to_string(),
        ))?;

    let credential_index = vec_last_position_from_token_path(&path_nested.path)?;
    let credential_token = presentation
        .credentials
        .get(credential_index)
        .ok_or(OpenID4VCIError::InvalidRequest)?;

    let oidc_format = &path_nested.format;
    let format = map_from_oidc_format_to_external(oidc_format, Some(credential_token))?;
    let formatter = formatter_provider
        .get_formatter(&format)
        .ok_or(OpenID4VCIError::VCFormatsNotSupported)?;

    let credential = formatter
        .extract_credentials(credential_token, key_verification)
        .await
        .map_err(|e| {
            if matches!(e, FormatterError::CouldNotExtractCredentials(_)) {
                OpenID4VCIError::VCFormatsNotSupported.into()
            } else {
                OpenID4VCError::Other(e.to_string())
            }
        })?;

    validate_issuance_time(&credential.valid_from, formatter.get_leeway())?;
    validate_expiration_time(&credential.valid_until, formatter.get_leeway())?;

    let issuer_did = credential
        .issuer_did
        .clone()
        .ok_or(OpenID4VCError::ValidationError(
            "Issuer DID missing".to_owned(),
        ))?;

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
                &issuer_did,
                Some(CredentialDataByRole::Verifier(Box::new(
                    VerifierCredentialData {
                        credential: credential.to_owned(),
                        extracted_lvvcs: extracted_lvvcs.to_owned(),
                        proof_input: proof_schema_input.to_owned(),
                    },
                ))),
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

    let claim_subject_did = did_method_provider
        .resolve(claim_subject)
        .await
        .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

    let holder_did = did_method_provider
        .resolve(holder_did)
        .await
        .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

    if claim_subject_did != holder_did {
        return Err(OpenID4VCError::ValidationError(
            "Holder DID doesn't match.".to_owned(),
        ));
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
    let expected_credential_claims = proof_input_schema
        .claim_schemas
        .as_ref()
        .ok_or(OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidRequest))?;

    let credential_schema = proof_input_schema
        .credential_schema
        .as_ref()
        .ok_or(OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidRequest))?;
    let mut proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();

    for expected_credential_claim in expected_credential_claims {
        let resolved = resolve_claim(
            &expected_credential_claim.schema.key,
            &received_credential.claims.values,
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
            return Err(OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidRequest));
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

pub(crate) fn throw_if_token_request_invalid(
    request: &OpenID4VCITokenRequestDTO,
) -> Result<(), OpenID4VCError> {
    match &request {
        OpenID4VCITokenRequestDTO::PreAuthorizedCode {
            pre_authorized_code,
        } if pre_authorized_code.is_empty() => {
            Err(OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidRequest))
        }
        OpenID4VCITokenRequestDTO::RefreshToken { refresh_token } if refresh_token.is_empty() => {
            Err(OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidRequest))
        }

        _ => Ok(()),
    }
}

pub(crate) fn throw_if_interaction_created_date(
    pre_authorization_expires_in: time::Duration,
    interaction: &Interaction,
) -> Result<(), OpenID4VCError> {
    if interaction.created_date + pre_authorization_expires_in < OffsetDateTime::now_utc() {
        return Err(OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidGrant));
    }
    Ok(())
}

pub(crate) fn throw_if_interaction_pre_authorized_code_used(
    interaction_data: &OpenID4VCIInteractionDataDTO,
) -> Result<(), OpenID4VCError> {
    if interaction_data.pre_authorized_code_used {
        return Err(OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidGrant));
    }
    Ok(())
}

pub(crate) fn throw_if_latest_credential_state_not_eq(
    credential: &Credential,
    state: CredentialStateEnum,
) -> Result<(), OpenID4VCError> {
    let latest_state = &credential
        .state
        .as_ref()
        .ok_or(OpenID4VCError::MappingError("state is None".to_string()))?
        .first()
        .as_ref()
        .ok_or(OpenID4VCError::MappingError("state is missing".to_string()))?
        .to_owned()
        .state;
    if *latest_state != state {
        return Err(OpenID4VCError::InvalidCredentialState {
            state: latest_state.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn validate_refresh_token(
    interaction_data: &OpenID4VCIInteractionDataDTO,
    refresh_token: &str,
) -> Result<(), OpenID4VCError> {
    let Some(stored_refresh_token) = interaction_data.refresh_token.as_ref() else {
        return Err(OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidRequest));
    };

    if refresh_token != stored_refresh_token {
        return Err(OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidToken));
    }

    let Some(expires_at) = interaction_data.refresh_token_expires_at.as_ref() else {
        return Err(OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidRequest));
    };

    if &OffsetDateTime::now_utc() > expires_at {
        return Err(OpenID4VCError::OpenID4VCI(OpenID4VCIError::InvalidToken));
    }

    Ok(())
}
