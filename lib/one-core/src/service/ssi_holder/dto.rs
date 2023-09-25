use crate::{
    model::{credential::CredentialId, interaction::InteractionId},
    service::{proof::dto::ProofId, ssi_verifier::dto::ConnectVerifierResponseDTO},
};

#[derive(Clone, Debug)]
pub enum InvitationResponseDTO {
    Credential {
        interaction_id: InteractionId,
        credential_id: CredentialId,
    },
    ProofRequest {
        interaction_id: InteractionId,
        proof_request: ConnectVerifierResponseDTO,
        proof_id: ProofId,
    },
}

#[derive(Clone, Debug)]
pub(super) struct HandleInvitationURLQuery {
    pub protocol: String,
}
