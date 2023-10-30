use crate::model::interaction::Interaction;
use crate::service::error::ServiceError;
use crate::service::oidc::dto::{
    OpenID4VCIError, OpenID4VCIInteractionDataDTO, OpenID4VCITokenRequestDTO,
};
use time::{Duration, OffsetDateTime};

pub(crate) fn validate_token_request(
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

pub(crate) fn check_interaction_created_date(
    pre_authorization_expires_in: Duration,
    interaction: &Interaction,
) -> Result<(), ServiceError> {
    if interaction.created_date + pre_authorization_expires_in < OffsetDateTime::now_utc() {
        return Err(ServiceError::OpenID4VCError(OpenID4VCIError::InvalidGrant));
    }
    Ok(())
}

pub(crate) fn check_interaction_pre_authorized_code_used(
    interaction_data: &OpenID4VCIInteractionDataDTO,
) -> Result<(), ServiceError> {
    if interaction_data.pre_authorized_code_used {
        return Err(ServiceError::OpenID4VCError(OpenID4VCIError::InvalidGrant));
    }
    Ok(())
}
