use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "claim_schemas")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    #[serde(skip_deserializing)]
    pub id: String,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: Datatype,

    pub credential_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    Credential,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::Credential => Entity::belongs_to(super::credential_schema::Entity)
                .from(Column::CredentialId)
                .to(super::credential_schema::Column::Id)
                .into(),
        }
    }
}

impl Related<super::credential_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

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
