use crate::data_model;
use chrono::{offset::Utc, DateTime};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[allow(non_snake_case)]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "claim_schemas")]
pub struct Model {
    #[sea_orm(primary_key)]
    #[serde(skip_deserializing)]
    pub id: i32,

    pub createdDate: DateTime<Utc>,
    pub lastModified: DateTime<Utc>,
    pub deletedAt: Option<DateTime<Utc>>,
    pub key: String,
    pub datatype: data_model::Datatype,

    pub credentialId: i32,
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
