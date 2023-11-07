use crate::model::credential_schema::CredentialSchema;
use crate::model::interaction::Interaction;
use crate::service::error::ServiceError;
use crate::service::oidc::dto::{
    OpenID4VCICredentialRequestDTO, OpenID4VCIError, OpenID4VCIInteractionDataDTO,
    OpenID4VCITokenRequestDTO,
};
use crate::util::oidc::map_from_oidc_format_to_core;
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
