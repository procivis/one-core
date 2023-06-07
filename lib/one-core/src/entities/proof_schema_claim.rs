use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "proof_schema_claims")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub claim_schema_id: u32,

    #[sea_orm(primary_key)]
    pub proof_schema_id: u32,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    ProofSchema,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::ProofSchema => Entity::belongs_to(super::proof_schema::Entity)
                .from(Column::ProofSchemaId)
                .to(super::proof_schema::Column::Id)
                .into(),
        }
    }
}

impl Related<super::proof_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofSchema.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
