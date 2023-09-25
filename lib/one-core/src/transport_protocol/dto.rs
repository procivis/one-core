use crate::service::credential::dto::CredentialResponseDTO;
use serde::{Deserialize, Serialize}; // serialization necessary for wallet to parse JSON API response
use time::OffsetDateTime;

#[derive(Clone)]
pub enum InvitationResponse {
    Credential(Box<CredentialResponseDTO>),
    Proof {
        proof_request: ConnectVerifierResponse,
        proof_id: String,
    },
}

#[derive(Clone, Deserialize)]
pub struct SubmitIssuerResponse {
    pub credential: String,
    pub format: String,
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

#[derive(Serialize)]
/// serializes matching `ConnectRequestRestDTO`
pub(super) struct HandleInvitationConnectRequest {
    pub did: String,
}
