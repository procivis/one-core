use std::collections::HashMap;

use shared_types::{CredentialId, DidId, KeyId};

use crate::model::interaction::InteractionId;

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
