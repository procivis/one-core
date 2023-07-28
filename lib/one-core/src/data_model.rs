use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::data_layer::data_model::{CredentialClaimSchemaResponse, ListCredentialSchemaResponse};

#[derive(Deserialize)]
pub struct ConnectIssuerRequest {
    pub credential: Uuid,
    pub did: String,
}

#[derive(Clone, Deserialize)]
pub struct ConnectIssuerResponse {
    pub credential: String,
    pub format: String, // As far as I know we will get rid of enums
}

pub struct ConnectVerifierRequest {
    pub proof: Uuid,
    pub did: String,
}

pub struct ConnectVerifierResponse {
    pub claims: Vec<ProofClaimSchema>,
}

pub struct ProofClaimSchema {
    pub schema: CredentialClaimSchemaResponse,
    pub required: bool,
    pub credential_schema: ListCredentialSchemaResponse,
}

#[derive(Deserialize)]
pub struct HandleInvitationQueryRequest {
    pub credential: Uuid,
    pub protocol: String, // As far as I know we will get rid of enums
}

#[derive(Serialize)]
pub struct HandleInvitationConnectRequest {
    pub did: String,
}
