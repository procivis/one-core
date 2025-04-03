use one_crypto::hasher::sha256::SHA256;
use one_crypto::Hasher;
use time::OffsetDateTime;

use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::interaction::Interaction;
use crate::provider::issuance_protocol::openid4vci_draft13::error::{
    OpenID4VCIError, OpenIDIssuanceError,
};
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    OpenID4VCIIssuerInteractionDataDTO, OpenID4VCITokenRequestDTO,
};

pub(crate) fn throw_if_token_request_invalid(
    request: &OpenID4VCITokenRequestDTO,
) -> Result<(), OpenIDIssuanceError> {
    match &request {
        OpenID4VCITokenRequestDTO::PreAuthorizedCode {
            pre_authorized_code,
            tx_code: _,
        } if pre_authorized_code.is_empty() => Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidRequest,
        )),
        OpenID4VCITokenRequestDTO::RefreshToken { refresh_token } if refresh_token.is_empty() => {
            Err(OpenIDIssuanceError::OpenID4VCI(
                OpenID4VCIError::InvalidRequest,
            ))
        }

        _ => Ok(()),
    }
}

pub(crate) fn throw_if_interaction_created_date(
    pre_authorization_expires_in: time::Duration,
    interaction: &Interaction,
) -> Result<(), OpenIDIssuanceError> {
    if interaction.created_date + pre_authorization_expires_in < OffsetDateTime::now_utc() {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidGrant,
        ));
    }
    Ok(())
}

pub(crate) fn throw_if_interaction_pre_authorized_code_used(
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
) -> Result<(), OpenIDIssuanceError> {
    if interaction_data.pre_authorized_code_used {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidGrant,
        ));
    }
    Ok(())
}

pub(crate) fn throw_if_credential_state_not_eq(
    credential: &Credential,
    state: CredentialStateEnum,
) -> Result<(), OpenIDIssuanceError> {
    let current_state = &credential.state;
    if *current_state != state {
        return Err(OpenIDIssuanceError::InvalidCredentialState {
            state: current_state.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn validate_refresh_token(
    interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
    refresh_token: &str,
) -> Result<(), OpenIDIssuanceError> {
    let Some(stored_refresh_token_hash) = interaction_data.refresh_token_hash.as_ref() else {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidRequest,
        ));
    };

    let refresh_token_hash = SHA256
        .hash(refresh_token.as_bytes())
        .map_err(|e| OpenIDIssuanceError::ValidationError(e.to_string()))?;

    if stored_refresh_token_hash != &refresh_token_hash {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidToken,
        ));
    }

    let Some(expires_at) = interaction_data.refresh_token_expires_at.as_ref() else {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidRequest,
        ));
    };

    if &OffsetDateTime::now_utc() > expires_at {
        return Err(OpenIDIssuanceError::OpenID4VCI(
            OpenID4VCIError::InvalidToken,
        ));
    }

    Ok(())
}
