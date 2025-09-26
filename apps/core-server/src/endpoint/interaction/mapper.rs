use one_core::service::error::ServiceError;
use one_core::service::ssi_holder::dto::{HandleInvitationResultDTO, InitiateIssuanceRequestDTO};
use one_dto_mapper::{convert_inner, convert_inner_of_inner};

use super::dto::HandleInvitationResponseRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::interaction::dto::InitiateIssuanceRequestRestDTO;

impl From<HandleInvitationResultDTO> for HandleInvitationResponseRestDTO {
    fn from(value: HandleInvitationResultDTO) -> Self {
        match value {
            HandleInvitationResultDTO::Credential {
                credential_ids,
                interaction_id,
                tx_code,
                credential_configurations_supported,
            } => Self {
                interaction_id,
                credential_ids: Some(credential_ids),
                proof_id: None,
                tx_code: convert_inner(tx_code),
                credential_configurations_supported: Some(convert_inner(
                    credential_configurations_supported,
                )),
                authorization_code_flow_url: None,
            },
            HandleInvitationResultDTO::AuthorizationCodeFlow {
                interaction_id,
                authorization_code_flow_url,
            } => Self {
                interaction_id,
                credential_ids: None,
                proof_id: None,
                tx_code: None,
                credential_configurations_supported: None,
                authorization_code_flow_url: Some(authorization_code_flow_url),
            },
            HandleInvitationResultDTO::ProofRequest {
                proof_id,
                interaction_id,
                ..
            } => Self {
                interaction_id,
                credential_ids: None,
                proof_id: Some(proof_id),
                tx_code: None,
                credential_configurations_supported: None,
                authorization_code_flow_url: None,
            },
        }
    }
}

impl TryFrom<InitiateIssuanceRequestRestDTO> for InitiateIssuanceRequestDTO {
    type Error = ServiceError;

    fn try_from(value: InitiateIssuanceRequestRestDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            organisation_id: fallback_organisation_id_from_session(value.organisation_id)?,
            protocol: value.protocol,
            issuer: value.issuer,
            client_id: value.client_id,
            redirect_uri: value.redirect_uri,
            scope: value.scope,
            authorization_details: convert_inner_of_inner(value.authorization_details),
            issuer_state: None,
            authorization_server: None,
        })
    }
}
