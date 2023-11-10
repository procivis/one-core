use crate::service::credential::dto::CredentialDetailResponseDTO;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub enum InvitationType {
    CredentialIssuance,
    ProofRequest,
}

#[derive(Clone, Deserialize)]
pub struct SubmitIssuerResponse {
    pub credential: String,
    pub format: String,
}

#[derive(Clone)]
pub enum InvitationResponse {
    Credential(Box<CredentialDetailResponseDTO>),
    Proof {
        proof_request: ConnectVerifierResponse,
        proof_id: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `ConnectVerifierResponseRestDTO`
pub struct ConnectVerifierResponse {
    pub claims: Vec<ProofClaimSchema>,
    pub verifier_did: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `ProofRequestClaimRestDTO`
pub struct ProofClaimSchema {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub credential_schema: ProofCredentialSchema,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `CredentialSchemaListValueResponseRestDTO`
pub struct ProofCredentialSchema {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
}
