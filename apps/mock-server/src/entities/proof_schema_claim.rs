use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "proof_schema_claims")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub claim_schema_id: String,

    #[sea_orm(primary_key, auto_increment = false)]
    pub proof_schema_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    ProofSchema,
    ClaimSchema,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::ProofSchema => Entity::belongs_to(super::proof_schema::Entity)
                .from(Column::ProofSchemaId)
                .to(super::proof_schema::Column::Id)
                .into(),
            Self::ClaimSchema => Entity::belongs_to(super::claim_schema::Entity)
                .from(Column::ClaimSchemaId)
                .to(super::claim_schema::Column::Id)
                .into(),
        }
    }
}

impl Related<super::proof_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofSchema.def()
    }
}

impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ClaimSchema.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
