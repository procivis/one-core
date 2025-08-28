use one_core::service::ssi_holder::dto::HandleInvitationResultDTO;
use one_dto_mapper::convert_inner;

use super::dto::HandleInvitationResponseRestDTO;

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
