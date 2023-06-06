use crate::entities::{claim_schema, credential_schema};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use time::macros::datetime;
use time::OffsetDateTime;
use utoipa::ToSchema;

#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    PartialEq,
    Serialize,
    ToSchema,
    EnumIter,
    DeriveActiveEnum,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
#[serde(rename_all = "UPPERCASE")]
pub enum RevocationMethod {
    #[default]
    #[sea_orm(string_value = "STATUSLIST2021")]
    StatusList2021,
    #[sea_orm(string_value = "LVVC")]
    Lvvc,
}

#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    PartialEq,
    Serialize,
    ToSchema,
    EnumIter,
    DeriveActiveEnum,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Format {
    #[default]
    #[sea_orm(string_value = "JWT")]
    Jwt,
    #[sea_orm(string_value = "SD_JWT")]
    SdJwt,
    #[sea_orm(string_value = "JSON_LD")]
    JsonLd,
    #[sea_orm(string_value = "MDOC")]
    Mdoc,
}

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

#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    PartialEq,
    Serialize,
    ToSchema,
    EnumIter,
    DeriveActiveEnum,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
#[serde(rename_all = "UPPERCASE")]
pub enum Datatype {
    #[default]
    #[sea_orm(string_value = "STRING")]
    String,
    #[sea_orm(string_value = "DATE")]
    Date,
    #[sea_orm(string_value = "NUMBER")]
    Number,
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

impl Default for CredentialSchemaResponseDTO {
    fn default() -> Self {
        Self {
            created_date: datetime!(1970-01-01 00:00 UTC),
            last_modified: datetime!(1970-01-01 00:00 UTC),
            ..Default::default()
        }
    }
}

impl Default for CredentialClaimSchemaResponseDTO {
    fn default() -> Self {
        Self {
            created_date: datetime!(1970-01-01 00:00 UTC),
            last_modified: datetime!(1970-01-01 00:00 UTC),
            ..Default::default()
        }
    }
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
        value
            .iter()
            .map(|claim_schema| Self::from_model(claim_schema))
            .collect()
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
