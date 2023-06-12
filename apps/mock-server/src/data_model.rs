use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

pub use crate::entities::claim_schema::Datatype;
pub use crate::entities::credential_schema::{Format, RevocationMethod};
use crate::entities::{claim_schema, credential_schema};

// TODO create proper serialization function when
time::serde::format_description!(
    front_time,
    OffsetDateTime,
    "[year]-[month]-[day padding:zero]T[hour padding:zero]:[minute padding:zero]:[second padding:zero].000Z"
);

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialSchemaRequestDTO {
    pub name: String,
    pub format: Format,
    pub revocation_method: RevocationMethod,
    pub organisation_id: Uuid,
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
    pub id: String,
    #[serde(with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: Format,
    pub revocation_method: RevocationMethod,
    pub organisation_id: String,
    pub claims: Vec<CredentialClaimSchemaResponseDTO>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialClaimSchemaResponseDTO {
    pub id: String,
    #[serde(with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: Datatype,
}

impl CredentialClaimSchemaResponseDTO {
    pub fn from_model(value: &claim_schema::Model) -> Self {
        Self {
            id: value.id.clone(),
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
            organisation_id: value.organisation_id,
            claims: CredentialClaimSchemaResponseDTO::from_vec(claim_schemas),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase")]
pub struct CreateProofSchemaRequestDTO {
    #[validate(length(min = 1))]
    pub name: String,
    pub organisation_id: Uuid,
    pub expire_duration: u32,
    pub claim_schemas: Vec<ClaimProofSchemaRequestDTO>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClaimProofSchemaRequestDTO {
    pub id: Uuid,
    pub is_required: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateProofSchemaResponseDTO {
    pub id: String,
}
