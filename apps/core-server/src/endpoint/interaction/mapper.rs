use one_core::service::error::ServiceError;
use one_core::service::ssi_holder::dto::{HandleInvitationResultDTO, InitiateIssuanceRequestDTO};
use one_dto_mapper::{convert_inner, convert_inner_of_inner};

use super::dto::{HandleInvitationResponseRestDTO, InteractionTypeRestEnum};
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::interaction::dto::InitiateIssuanceRequestRestDTO;

impl From<HandleInvitationResultDTO> for HandleInvitationResponseRestDTO {
    fn from(value: HandleInvitationResultDTO) -> Self {
        match value {
            HandleInvitationResultDTO::Credential {
                interaction_id,
                tx_code,
                key_storage_security,
                key_algorithms,
            } => Self {
                interaction_id,
                proof_id: None,
                tx_code: convert_inner(tx_code),
                interaction_type: InteractionTypeRestEnum::Issuance,
                authorization_code_flow_url: None,
                key_storage_security: convert_inner_of_inner(key_storage_security),
                key_algorithms,
            },
            HandleInvitationResultDTO::AuthorizationCodeFlow {
                interaction_id,
                authorization_code_flow_url,
            } => Self {
                interaction_id,
                interaction_type: InteractionTypeRestEnum::Issuance,
                proof_id: None,
                tx_code: None,
                authorization_code_flow_url: Some(authorization_code_flow_url),
                key_storage_security: None,
                key_algorithms: None,
            },
            HandleInvitationResultDTO::ProofRequest {
                proof_id,
                interaction_id,
            } => Self {
                interaction_id,
                interaction_type: InteractionTypeRestEnum::Verification,
                proof_id: Some(proof_id),
                tx_code: None,
                authorization_code_flow_url: None,
                key_storage_security: None,
                key_algorithms: None,
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
