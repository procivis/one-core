use chrono::{offset::Utc, DateTime};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use super::super::data_model::{Format, RevocationMethod};

#[allow(non_snake_case)]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "credential_schemas")]
pub struct Model {
    #[sea_orm(primary_key)]
    #[serde(skip_deserializing)]
    pub id: i32,

    pub deletedAt: Option<DateTime<Utc>>,
    pub createdDate: DateTime<Utc>,
    pub lastModified: DateTime<Utc>,
    pub name: String,
    pub format: Format,
    pub revocationMethod: RevocationMethod,
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
