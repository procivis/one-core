use std::collections::HashMap;
use std::sync::Arc;

use time::{Duration, OffsetDateTime};

use super::dto::ValidatedProofClaimDTO;
use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::common_validator::{validate_expiration_time, validate_issuance_time};
use crate::config::core_config::{CoreConfig, ExchangeType};
use crate::config::ConfigValidationError;
use crate::model::credential_schema::CredentialSchema;
use crate::model::interaction::Interaction;
use crate::model::proof_schema::ProofInputSchema;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{DetailCredential, Presentation};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::{ExtractPresentationCtx, TokenVerifier};
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::revocation::{
    CredentialDataByRole, CredentialRevocationState, VerifierCredentialData,
};
use crate::service::error::{BusinessLogicError, MissingProviderError, ServiceError};
use crate::service::oidc::dto::{
    NestedPresentationSubmissionDescriptorDTO, OpenID4VCICredentialRequestDTO, OpenID4VCIError,
    OpenID4VCIInteractionDataDTO, OpenID4VCITokenRequestDTO,
};
use crate::service::oidc::mapper::vec_last_position_from_token_path;
use crate::util::key_verification::KeyVerification;
use crate::util::oidc::{
    map_from_oidc_format_to_core, map_from_oidc_format_to_core_real,
    map_from_oidc_vp_format_to_core,
};

pub(crate) fn throw_if_token_request_invalid(
    request: &OpenID4VCITokenRequestDTO,
) -> Result<(), ServiceError> {
    match &request {
        OpenID4VCITokenRequestDTO::PreAuthorizedCode {
            pre_authorized_code,
        } if pre_authorized_code.is_empty() => Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::InvalidRequest,
        )),
        OpenID4VCITokenRequestDTO::RefreshToken { refresh_token } if refresh_token.is_empty() => {
            Err(ServiceError::OpenID4VCError(
                OpenID4VCIError::InvalidRequest,
            ))
        }

        _ => Ok(()),
    }
}

pub(crate) fn throw_if_interaction_created_date(
    pre_authorization_expires_in: Duration,
    interaction: &Interaction,
) -> Result<(), ServiceError> {
    if interaction.created_date + pre_authorization_expires_in < OffsetDateTime::now_utc() {
        return Err(ServiceError::OpenID4VCError(OpenID4VCIError::InvalidGrant));
    }
    Ok(())
}

pub(crate) fn throw_if_interaction_pre_authorized_code_used(
    interaction_data: &OpenID4VCIInteractionDataDTO,
) -> Result<(), ServiceError> {
    if interaction_data.pre_authorized_code_used {
        return Err(ServiceError::OpenID4VCError(OpenID4VCIError::InvalidGrant));
    }
    Ok(())
}

pub(crate) fn throw_if_credential_request_invalid(
    schema: &CredentialSchema,
    request: &OpenID4VCICredentialRequestDTO,
) -> Result<(), ServiceError> {
    let requested_format = map_from_oidc_format_to_core(&request.format)?;

    if !schema.format.starts_with(&requested_format) {
        return Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::UnsupportedCredentialFormat,
        ));
    }

    match requested_format.as_str() {
        "MDOC" => {
            if let Some(doctype) = &request.doctype {
                if &schema.schema_id != doctype {
                    return Err(ServiceError::OpenID4VCError(
                        OpenID4VCIError::UnsupportedCredentialType,
                    ));
                }
            } else {
                return Err(ServiceError::OpenID4VCError(
                    OpenID4VCIError::InvalidRequest,
                ));
            }
        }
        _ => {
            if !request
                .credential_definition
                .as_ref()
                .ok_or(ServiceError::OpenID4VCError(
                    OpenID4VCIError::InvalidRequest,
                ))?
                .r#type
                .contains(&"VerifiableCredential".to_string())
            {
                return Err(ServiceError::OpenID4VCError(
                    OpenID4VCIError::UnsupportedCredentialType,
                ));
            }
        }
    };

    Ok(())
}

fn is_interaction_data_valid(
    interaction_data: &OpenID4VCIInteractionDataDTO,
    access_token: &str,
) -> bool {
    interaction_data.pre_authorized_code_used
        && interaction_data.access_token == access_token
        && interaction_data
            .access_token_expires_at
            .is_some_and(|expires_at| expires_at > OffsetDateTime::now_utc())
}

pub(crate) fn throw_if_interaction_data_invalid(
    interaction_data: &OpenID4VCIInteractionDataDTO,
    access_token: &str,
) -> Result<(), ServiceError> {
    if !is_interaction_data_valid(interaction_data, access_token) {
        return Err(ServiceError::OpenID4VCError(OpenID4VCIError::InvalidToken));
    }
    Ok(())
}

pub(super) async fn peek_presentation(
    presentation_string: &str,
    oidc_format: &str,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
) -> Result<Presentation, ServiceError> {
    let format = map_from_oidc_vp_format_to_core(oidc_format)?;
    let formatter = formatter_provider
        .get_formatter(&format)
        .ok_or(OpenID4VCIError::VCFormatsNotSupported)?;

    let presentation = formatter
        .extract_presentation_unverified(presentation_string, ExtractPresentationCtx::empty())
        .await
        .map_err(|e| {
            if matches!(e, FormatterError::CouldNotExtractPresentation(_)) {
                OpenID4VCIError::VPFormatsNotSupported.into()
            } else {
                ServiceError::Other(e.to_string())
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
) -> Result<Presentation, ServiceError> {
    let format = map_from_oidc_vp_format_to_core(oidc_format)?;
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
                ServiceError::Other(e.to_string())
            }
        })?;

    validate_issuance_time(&presentation.issued_at, formatter.get_leeway())?;
    validate_expiration_time(&presentation.expires_at, formatter.get_leeway())?;

    if !presentation
        .nonce
        .as_ref()
        .is_some_and(|presentation_nonce| presentation_nonce == nonce)
    {
        return Err(ServiceError::ValidationError(
            "Nonce not matched".to_string(),
        ));
    }

    Ok(presentation)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn validate_credential(
    presentation: Presentation,
    path_nested: &NestedPresentationSubmissionDescriptorDTO,
    extracted_lvvcs: &[DetailCredential],
    proof_schema_input: &ProofInputSchema,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    key_verification: Box<KeyVerification>,
    revocation_method_provider: &Arc<dyn RevocationMethodProvider>,
) -> Result<DetailCredential, ServiceError> {
    let holder_did = presentation
        .issuer_did
        .as_ref()
        .ok_or(ServiceError::ValidationError(
            "Missing holder id".to_string(),
        ))?;

    let credential_index = vec_last_position_from_token_path(&path_nested.path)?;
    let credential = presentation
        .credentials
        .get(credential_index)
        .ok_or(OpenID4VCIError::InvalidRequest)?;

    let oidc_format = &path_nested.format;
    let format = map_from_oidc_format_to_core_real(oidc_format, credential)?;
    let formatter = formatter_provider
        .get_formatter(&format)
        .ok_or(OpenID4VCIError::VCFormatsNotSupported)?;

    let credential = formatter
        .extract_credentials(credential, key_verification)
        .await
        .map_err(|e| {
            if matches!(e, FormatterError::CouldNotExtractCredentials(_)) {
                OpenID4VCIError::VCFormatsNotSupported.into()
            } else {
                ServiceError::Other(e.to_string())
            }
        })?;

    validate_issuance_time(&credential.issued_at, formatter.get_leeway())?;
    validate_expiration_time(&credential.expires_at, formatter.get_leeway())?;

    let issuer_did = credential
        .issuer_did
        .clone()
        .ok_or(ServiceError::ValidationError(
            "Issuer DID missing".to_owned(),
        ))?;

    for credential_status in credential.status.iter() {
        let (revocation_method, _) = revocation_method_provider
            .get_revocation_method_by_status_type(&credential_status.r#type)
            .ok_or(
                MissingProviderError::RevocationMethodByCredentialStatusType(
                    credential_status.r#type.clone(),
                ),
            )?;

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
                return Err(BusinessLogicError::CredentialIsRevokedOrSuspended.into());
            }
        }
    }

    // Check if all subjects of the submitted VCs is matching the holder did.
    let claim_subject = match &credential.subject {
        None => {
            return Err(ServiceError::ValidationError(
                "Claim Holder DID missing".to_owned(),
            ));
        }
        Some(did) => did,
    };

    if claim_subject != holder_did {
        return Err(ServiceError::ValidationError(
            "Holder DID doesn't match.".to_owned(),
        ));
    }
    Ok(credential)
}

fn resolve_claim<'a>(
    claim_name: &str,
    claims: &'a HashMap<String, serde_json::Value>,
) -> Result<Option<&'a serde_json::Value>, ServiceError> {
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
) -> Result<Option<&'a serde_json::Value>, ServiceError> {
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

pub(super) fn validate_claims(
    received_credential: DetailCredential,
    //descriptor: &OpenID4VPPresentationDefinitionInputDescriptor,
    proof_input_schema: &ProofInputSchema,
) -> Result<Vec<ValidatedProofClaimDTO>, ServiceError> {
    let expected_credential_claims =
        proof_input_schema
            .claim_schemas
            .as_ref()
            .ok_or(ServiceError::OpenID4VCError(
                OpenID4VCIError::InvalidRequest,
            ))?;

    let credential_schema =
        proof_input_schema
            .credential_schema
            .as_ref()
            .ok_or(ServiceError::OpenID4VCError(
                OpenID4VCIError::InvalidRequest,
            ))?;
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
            })
        } else if expected_credential_claim.required {
            // Fail as required claim was not sent
            return Err(ServiceError::OpenID4VCError(
                OpenID4VCIError::InvalidRequest,
            ));
        } else {
            // Not present but also not required
            continue;
        }
    }
    Ok(proved_claims)
}

pub(super) fn validate_config_entity_presence(
    config: &CoreConfig,
) -> Result<(), ConfigValidationError> {
    if !config
        .exchange
        .iter()
        .any(|(_, v)| v.r#type == ExchangeType::OpenId4Vc)
    {
        Err(ConfigValidationError::KeyNotFound(
            "No exchange method with type OPENID4VC".to_string(),
        ))
    } else {
        Ok(())
    }
}

pub(super) fn validate_refresh_token(
    interaction_data: &OpenID4VCIInteractionDataDTO,
    refresh_token: &str,
) -> Result<(), ServiceError> {
    let Some(stored_refresh_token) = interaction_data.refresh_token.as_ref() else {
        return Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::InvalidRequest,
        ));
    };

    if refresh_token != stored_refresh_token {
        return Err(ServiceError::OpenID4VCError(OpenID4VCIError::InvalidToken));
    }

    let Some(expires_at) = interaction_data.refresh_token_expires_at.as_ref() else {
        return Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::InvalidRequest,
        ));
    };

    if &OffsetDateTime::now_utc() > expires_at {
        return Err(ServiceError::OpenID4VCError(OpenID4VCIError::InvalidToken));
    }

    Ok(())
}
