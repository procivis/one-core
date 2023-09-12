use serde::{Deserialize, Serialize}; // serialization necessary for wallet to parse JSON API response
use time::OffsetDateTime;

#[derive(Clone)]
pub enum InvitationResponse {
    Credential(ConnectIssuerResponse),
    Proof {
        proof_request: ConnectVerifierResponse,
        proof_id: String,
    },
}

#[derive(Clone, Deserialize)]
/// deserializes matching `ConnectIssuerResponseRestDTO`
pub struct ConnectIssuerResponse {
    pub credential: String,
    pub format: String,
}

#[derive(Clone, Deserialize)]
/// deserializes matching `ConnectVerifierResponseRestDTO`
pub struct ConnectVerifierResponse {
    pub claims: Vec<ProofClaimSchema>,
}

#[derive(Clone, Deserialize)]
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

#[derive(Clone, Debug, Deserialize)]
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
