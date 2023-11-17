use std::sync::Arc;

use crate::common_validator::{validate_expiration_time, validate_issuance_time};
use crate::model::credential_schema::CredentialSchema;
use crate::model::interaction::Interaction;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{DetailCredential, Presentation};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::service::error::ServiceError;
use crate::service::oidc::dto::{
    OpenID4VCICredentialRequestDTO, OpenID4VCIError, OpenID4VCIInteractionDataDTO,
    OpenID4VCITokenRequestDTO,
};
use crate::util::key_verification::KeyVerification;
use crate::util::oidc::{map_from_oidc_format_to_core, map_from_oidc_vp_format_to_core};
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};

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
    if schema.format != map_from_oidc_format_to_core(&request.format)? {
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

pub(super) async fn validate_presentation(
    presentation_string: &str,
    nonce: &str,
    oidc_format: &str,
    formatter_provider: &Arc<dyn CredentialFormatterProvider + Send + Sync>,
    key_verification: Box<KeyVerification>,
) -> Result<Presentation, ServiceError> {
    let format = map_from_oidc_vp_format_to_core(oidc_format)?;
    let formatter = formatter_provider.get_formatter(&format).map_err(|e| {
        if matches!(e, ServiceError::NotFound) {
            OpenID4VCIError::VCFormatsNotSupported.into()
        } else {
            ServiceError::Other(e.to_string())
        }
    })?;

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

    validate_issuance_time(presentation.issued_at, formatter.get_leeway())?;
    validate_expiration_time(presentation.expires_at, formatter.get_leeway())?;

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
    credential_string: &str,
    holder_did: &DidValue,
    oidc_format: &str,
    formatter_provider: &Arc<dyn CredentialFormatterProvider + Send + Sync>,
    key_verification: Box<KeyVerification>,
    revocation_method_provider: &Arc<dyn RevocationMethodProvider + Send + Sync>,
) -> Result<DetailCredential, ServiceError> {
    let format = map_from_oidc_format_to_core(oidc_format)?;
    let formatter = formatter_provider.get_formatter(&format).map_err(|e| {
        if matches!(e, ServiceError::NotFound) {
            OpenID4VCIError::VCFormatsNotSupported.into()
        } else {
            ServiceError::Other(e.to_string())
        }
    })?;

    let credential = formatter
        .extract_credentials(credential_string, key_verification)
        .await
        .map_err(|e| {
            if matches!(e, FormatterError::CouldNotExtractCredentials(_)) {
                OpenID4VCIError::VCFormatsNotSupported.into()
            } else {
                ServiceError::Other(e.to_string())
            }
        })?;

    validate_issuance_time(credential.issued_at, formatter.get_leeway())?;
    validate_expiration_time(credential.expires_at, formatter.get_leeway())?;

    if let Some(credential_status) = &credential.status {
        let (revocation_method, _) = revocation_method_provider
            .get_revocation_method_by_status_type(&credential_status.r#type)?;

        let issuer_did = credential
            .issuer_did
            .clone()
            .ok_or(ServiceError::ValidationError(
                "Issuer DID missing".to_owned(),
            ))?;

        if revocation_method
            .check_credential_revocation_status(credential_status, &issuer_did)
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

    if claim_subject != holder_did.as_str() {
        return Err(ServiceError::ValidationError(
            "Holder DID doesn't match.".to_owned(),
        ));
    }

    Ok(credential)
}
