use crate::{
    model::{credential::CredentialId, interaction::InteractionId},
    service::proof::dto::ProofId,
};

#[derive(Clone, Debug)]
pub enum InvitationResponseDTO {
    Credential {
        interaction_id: InteractionId,
        credential_ids: Vec<CredentialId>,
    },
    ProofRequest {
        interaction_id: InteractionId,
        proof_id: ProofId,
    },
}

#[derive(Clone, Debug)]
pub(super) struct HandleInvitationURLQuery {
    pub protocol: String,
}
