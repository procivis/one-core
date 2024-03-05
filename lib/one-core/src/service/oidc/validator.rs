use std::collections::HashMap;

use std::sync::Arc;

use crate::common_validator::{validate_expiration_time, validate_issuance_time};
use crate::config::core_config::{CoreConfig, ExchangeType};
use crate::config::ConfigValidationError;
use crate::model::claim_schema::ClaimSchemaId;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaId};
use crate::model::interaction::Interaction;
use crate::model::proof_schema::{ProofSchema, ProofSchemaClaim};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{DetailCredential, Presentation};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::TokenVerifier;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::revocation::{CredentialDataByRole, VerifierCredentialData};
use crate::service::error::{MissingProviderError, ServiceError};
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

use time::{Duration, OffsetDateTime};

use super::dto::ValidatedProofClaimDTO;
use super::model::OpenID4VPPresentationDefinitionInputDescriptor;

pub(crate) fn throw_if_token_request_invalid(
    request: &OpenID4VCITokenRequestDTO,
) -> Result<(), ServiceError> {
    if request.grant_type.is_empty() || request.pre_authorized_code.is_empty() {
        return Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::InvalidRequest,
        ));
    }

    if request.grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
        return Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::UnsupportedGrantType,
        ));
    }
    Ok(())
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
    if !schema
        .format
        .starts_with(&map_from_oidc_format_to_core(&request.format)?)
    {
        return Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::UnsupportedCredentialFormat,
        ));
    }

    if !request
        .credential_definition
        .r#type
        .contains(&"VerifiableCredential".to_string())
    {
        return Err(ServiceError::OpenID4VCError(
            OpenID4VCIError::UnsupportedCredentialType,
        ));
    }

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
        .extract_presentation_unverified(presentation_string)
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
) -> Result<Presentation, ServiceError> {
    let format = map_from_oidc_vp_format_to_core(oidc_format)?;
    let formatter = formatter_provider
        .get_formatter(&format)
        .ok_or(OpenID4VCIError::VCFormatsNotSupported)?;

    let presentation = formatter
        .extract_presentation(presentation_string, key_verification)
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

pub(super) async fn validate_credential(
    presentation: Presentation,
    path_nested: &NestedPresentationSubmissionDescriptorDTO,
    extracted_lvvcs: &[DetailCredential],
    proof_schema: &ProofSchema,
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

    if let Some(credential_status) = &credential.status {
        let (revocation_method, _) = revocation_method_provider
            .get_revocation_method_by_status_type(&credential_status.r#type)
            .ok_or(
                MissingProviderError::RevocationMethodByCredentialStatusType(
                    credential_status.r#type.clone(),
                ),
            )?;

        let issuer_did = credential
            .issuer_did
            .clone()
            .ok_or(ServiceError::ValidationError(
                "Issuer DID missing".to_owned(),
            ))?;

        if revocation_method
            .check_credential_revocation_status(
                credential_status,
                &issuer_did,
                Some(CredentialDataByRole::Verifier(Box::new(
                    VerifierCredentialData {
                        credential: credential.to_owned(),
                        extracted_lvvcs: extracted_lvvcs.to_owned(),
                        proof_schema: proof_schema.to_owned(),
                    },
                ))),
            )
            .await?
        {
            return Err(ServiceError::ValidationError(
                "Submitted credential revoked".to_owned(),
            ));
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

pub(super) fn validate_claims(
    received_credential: DetailCredential,
    descriptor: &OpenID4VPPresentationDefinitionInputDescriptor,
    claim_to_credential_schema_mapping: &HashMap<ClaimSchemaId, CredentialSchemaId>,
    expected_credential_claims: &HashMap<CredentialSchemaId, Vec<&ProofSchemaClaim>>,
) -> Result<Vec<ValidatedProofClaimDTO>, ServiceError> {
    // each descriptor contains only fields from a single credential_schema...
    let first_claim_schema = descriptor
        .constraints
        .fields
        // ... so one field is enough to find the proper credential_schema (and requested claims from that schema)
        .first()
        .ok_or(ServiceError::OpenID4VCError(
            OpenID4VCIError::InvalidRequest,
        ))?;

    let expected_credential_schema_id = claim_to_credential_schema_mapping
        .get(&first_claim_schema.id)
        .ok_or(ServiceError::OpenID4VCError(
            OpenID4VCIError::InvalidRequest,
        ))?;

    let expected_credential_claims = expected_credential_claims
        .get(expected_credential_schema_id)
        .ok_or(ServiceError::OpenID4VCError(
            OpenID4VCIError::InvalidRequest,
        ))?;

    let mut proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();
    for &expected_credential_claim in expected_credential_claims {
        if let Some(value) = received_credential
            .claims
            .values
            .get(&expected_credential_claim.schema.key)
        {
            // Expected claim present in the presentation
            proved_claims.push(ValidatedProofClaimDTO {
                claim_schema: expected_credential_claim.to_owned(),
                credential: received_credential.to_owned(),
                value: value.to_owned(),
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

pub(super) fn validate_transport_type(
    config: &CoreConfig,
    transport: &str,
) -> Result<(), ConfigValidationError> {
    let transport_type = config.exchange.get_fields(transport)?.r#type;

    if transport_type != ExchangeType::OpenId4Vc {
        Err(ConfigValidationError::InvalidType(
            ExchangeType::OpenId4Vc.to_string(),
            transport.to_string(),
        ))
    } else {
        Ok(())
    }
}
