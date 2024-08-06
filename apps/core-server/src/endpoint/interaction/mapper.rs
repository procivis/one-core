use one_providers::exchange_protocol::openid4vc::model::InvitationResponseDTO;

use super::dto::HandleInvitationResponseRestDTO;

impl From<InvitationResponseDTO> for HandleInvitationResponseRestDTO {
    fn from(value: InvitationResponseDTO) -> Self {
        match value {
            InvitationResponseDTO::Credential {
                credentials,
                interaction_id,
            } => Self {
                interaction_id: interaction_id.into(),
                credential_ids: Some(
                    credentials
                        .into_iter()
                        .map(|credential| credential.id.into())
                        .collect(),
                ),
                proof_id: None,
            },
            InvitationResponseDTO::ProofRequest {
                proof,
                interaction_id,
                ..
            } => Self {
                interaction_id: interaction_id.into(),
                credential_ids: None,
                proof_id: Some(proof.id.into()),
            },
        }
    }
}
