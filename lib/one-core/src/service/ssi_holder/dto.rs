use crate::{
    model::{credential::CredentialId, interaction::InteractionId},
    service::proof::dto::ProofId,
};
use std::collections::HashMap;

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
pub struct PresentationSubmitRequestDTO {
    pub interaction_id: InteractionId,
    pub submit_credentials: HashMap<String, PresentationSubmitCredentialRequestDTO>,
}

#[derive(Clone, Debug)]
pub struct PresentationSubmitCredentialRequestDTO {
    pub credential_id: CredentialId,
    pub submit_claims: Vec<String>,
}
