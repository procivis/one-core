use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "credential_schemas")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    #[sea_orm(primary_key)]
    #[serde(skip_deserializing)]
    pub id: u32,

    pub deleted_at: Option<OffsetDateTime>,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: Format,
    pub revocation_method: RevocationMethod,
    pub organisation_id: u32,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    Claim,
}

impl ActiveModelBehavior for ActiveModel {}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::Claim => Entity::has_many(super::claim_schema::Entity).into(),
        }
    }
}
impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Claim.def()
    }
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
