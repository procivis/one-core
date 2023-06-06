use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

pub use one_core::entities::claim_schema::Datatype;
pub use one_core::entities::credential_schema::{Format, RevocationMethod};
use one_core::entities::{claim_schema, credential_schema};

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialSchemaRequestDTO {
    pub name: String,
    pub format: Format,
    pub revocation_method: RevocationMethod,
    pub organisation_id: String,
    pub claims: Vec<CredentialClaimSchemaRequestDTO>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct CredentialClaimSchemaRequestDTO {
    pub key: String,
    pub datatype: Datatype,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetCredentialClaimSchemaResponseDTO {
    pub values: Vec<CredentialSchemaResponseDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaResponseDTO {
    pub id: u32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: Format,
    pub revocation_method: RevocationMethod,
    pub organisation_id: String,
    pub claims: Vec<CredentialClaimSchemaResponseDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct CredentialClaimSchemaResponseDTO {
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: Datatype,
}

impl CredentialClaimSchemaResponseDTO {
    pub fn from_model(value: &claim_schema::Model) -> Self {
        Self {
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key.clone(),
            datatype: value.datatype.clone(),
        }
    }

    pub fn from_vec(value: Vec<claim_schema::Model>) -> Vec<Self> {
        value.iter().map(Self::from_model).collect()
    }
}

impl CredentialSchemaResponseDTO {
    pub fn from_model(
        value: credential_schema::Model,
        claim_schemas: Vec<claim_schema::Model>,
    ) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            organisation_id: value.organisation_id.to_string(),
            claims: CredentialClaimSchemaResponseDTO::from_vec(claim_schemas),
        }
    }
}
