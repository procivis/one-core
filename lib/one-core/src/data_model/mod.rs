use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[allow(non_camel_case_types)]
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
pub enum RevocationMethod {
    #[default]
    #[sea_orm(string_value = "STATUSLIST2021")]
    STATUSLIST2021,
    #[sea_orm(string_value = "LVVC")]
    LVVC,
}

#[allow(non_camel_case_types)]
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
pub enum Format {
    #[default]
    #[sea_orm(string_value = "JWT")]
    JWT,
    #[sea_orm(string_value = "SD_JWT")]
    SD_JWT,
    #[sea_orm(string_value = "JSON_LD")]
    JSON_LD,
    #[sea_orm(string_value = "MDOC")]
    MDOC,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
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
pub enum Datatype {
    #[default]
    #[sea_orm(string_value = "STRING")]
    STRING,
    #[sea_orm(string_value = "DATE")]
    DATE,
    #[sea_orm(string_value = "NUMBER")]
    NUMBER,
}
