use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::data_model::{Format, RevocationMethod};

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
