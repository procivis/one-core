use super::dto::HandleInvitationResponseRestDTO;
use one_core::service::ssi_holder::dto::InvitationResponseDTO;

impl From<InvitationResponseDTO> for HandleInvitationResponseRestDTO {
    fn from(value: InvitationResponseDTO) -> Self {
        match value {
            InvitationResponseDTO::Credential {
                credentials,
                interaction_id,
            } => Self {
                interaction_id,
                credential_ids: Some(
                    credentials
                        .into_iter()
                        .map(|credential| credential.id)
                        .collect(),
                ),
                proof_id: None,
            },
            InvitationResponseDTO::ProofRequest {
                proof,
                interaction_id,
                ..
            } => Self {
                interaction_id,
                credential_ids: None,
                proof_id: Some(proof.id),
            },
        }
    }
}
