use super::dto::{HandleInvitationResponseRestDTO, PresentationSubmitRequestRestDTO};
use one_core::service::ssi_holder::dto::{InvitationResponseDTO, PresentationSubmitRequestDTO};

impl From<InvitationResponseDTO> for HandleInvitationResponseRestDTO {
    fn from(value: InvitationResponseDTO) -> Self {
        match value {
            InvitationResponseDTO::Credential {
                credential_ids,
                interaction_id,
            } => Self {
                interaction_id,
                credential_ids: Some(credential_ids),
                proof_id: None,
            },
            InvitationResponseDTO::ProofRequest {
                proof_id,
                interaction_id,
                ..
            } => Self {
                interaction_id,
                credential_ids: None,
                proof_id: Some(proof_id),
            },
        }
    }
}

impl From<PresentationSubmitRequestRestDTO> for PresentationSubmitRequestDTO {
    fn from(value: PresentationSubmitRequestRestDTO) -> Self {
        Self {
            interaction_id: value.interaction_id,
            submit_credentials: value
                .submit_credentials
                .into_iter()
                .map(|(key, value)| (key, value.into()))
                .collect(),
        }
    }
}
