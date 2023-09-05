use crate::{
    repository::data_provider::ListCredentialSchemaResponse,
    service::credential_schema::dto::GetCredentialSchemaListValueResponseDTO,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

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

#[derive(Clone, Serialize, Deserialize)] // serialization necessary for wallet to parse JSON API response
pub struct ConnectVerifierResponse {
    pub claims: Vec<ProofClaimSchema>,
}

#[derive(Clone, Serialize, Deserialize)] // serialization necessary for wallet to parse JSON API response
#[serde(rename_all = "camelCase")]
pub struct ProofClaimSchema {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub credential_schema: ListCredentialSchemaResponse,
}

#[derive(Deserialize)]
pub struct HandleInvitationQueryRequest {
    pub credential: Option<Uuid>,
    pub proof: Option<Uuid>,
    pub protocol: String,
}

#[derive(Serialize)]
pub struct HandleInvitationConnectRequest {
    pub did: String,
}

pub struct VerifierSubmitRequest {
    pub proof: Uuid,
    pub proof_submit_request: String,
}

impl From<GetCredentialSchemaListValueResponseDTO> for ListCredentialSchemaResponse {
    fn from(value: GetCredentialSchemaListValueResponseDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            organisation_id: "unknown".to_string(), // FIXME
        }
    }
}
