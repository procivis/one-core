use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "proof_schema")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    #[serde(skip_deserializing)]
    pub id: String,

    pub deleted_at: Option<OffsetDateTime>,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub expire_duration: u32,

    pub organisation_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        super::proof_schema_claim::Relation::ClaimSchema.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::proof_schema_claim::Relation::ProofSchema.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
