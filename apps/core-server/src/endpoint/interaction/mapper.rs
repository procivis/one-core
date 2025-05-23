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
            } => Self {
                interaction_id,
                credential_ids: Some(credential_ids),
                proof_id: None,
                tx_code: convert_inner(tx_code),
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
            },
        }
    }
}
