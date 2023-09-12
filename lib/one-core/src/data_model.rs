use crate::service::credential_schema::dto::GetCredentialSchemaListValueResponseDTO;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Deserialize)]
pub struct ConnectIssuerResponse {
    pub credential: String,
    pub format: String, // As far as I know we will get rid of enums
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")] // serialization necessary for wallet to parse JSON API response
pub struct ListCredentialSchemaResponse {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: String,
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
