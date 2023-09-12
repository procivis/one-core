use crate::{
    model::credential::CredentialId,
    service::{proof::dto::ProofId, ssi_verifier::dto::ConnectVerifierResponseDTO},
};

#[derive(Clone, Debug)]
pub enum InvitationResponseDTO {
    Credential {
        issued_credential_id: CredentialId,
    },
    ProofRequest {
        proof_request: ConnectVerifierResponseDTO,
        proof_id: ProofId,
        base_url: String,
    },
}

#[derive(Clone, Debug)]
pub(super) struct HandleInvitationURLQuery {
    pub credential: Option<CredentialId>,
    pub _proof: Option<ProofId>,
    pub protocol: String,
}
