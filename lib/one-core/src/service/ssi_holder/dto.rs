use dto_mapper::From;
use shared_types::{CredentialId, DidId, KeyId};

use crate::config::core_config::ExchangeType;
use crate::model::{credential::Credential, interaction::InteractionId, proof::Proof};
use crate::provider::exchange_protocol::dto::InvitationType;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub enum InvitationResponseDTO {
    Credential {
        interaction_id: InteractionId,
        credentials: Vec<Credential>,
    },
    ProofRequest {
        interaction_id: InteractionId,
        proof: Box<Proof>, // https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant
    },
}

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
pub struct CheckInvitationResponseDTO {
    pub r#type: CheckInvitationTypeDTO,
    pub protocol: CheckInvitationProtocolDTO,
}

#[derive(Clone, Debug, From)]
#[from(InvitationType)]
pub enum CheckInvitationTypeDTO {
    CredentialIssuance,
    ProofRequest,
}

#[derive(Clone, Debug, From)]
#[from(ExchangeType)]
pub enum CheckInvitationProtocolDTO {
    OpenId4Vc,
    ProcivisTemporary,
    Mdl,
}
