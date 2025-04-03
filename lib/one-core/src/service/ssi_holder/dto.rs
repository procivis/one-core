use std::collections::HashMap;

use shared_types::{CredentialId, DidId, KeyId, ProofId};

use crate::model::interaction::InteractionId;
use crate::provider::issuance_protocol::openid4vci_draft13::model::OpenID4VCITxCode;

#[derive(Clone, Debug)]
pub struct PresentationSubmitRequestDTO {
    pub interaction_id: InteractionId,
    pub submit_credentials: HashMap<String, PresentationSubmitCredentialRequestDTO>,
    pub did_id: DidId,
    pub key_id: Option<KeyId>,
}

#[derive(Clone, Debug)]
pub struct PresentationSubmitCredentialRequestDTO {
    pub credential_id: CredentialId,
    pub submit_claims: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum HandleInvitationResultDTO {
    Credential {
        interaction_id: InteractionId,
        credential_ids: Vec<CredentialId>,
        tx_code: Option<OpenID4VCITxCode>,
    },
    ProofRequest {
        interaction_id: InteractionId,
        proof_id: ProofId,
    },
}
