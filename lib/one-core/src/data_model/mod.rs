use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
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
