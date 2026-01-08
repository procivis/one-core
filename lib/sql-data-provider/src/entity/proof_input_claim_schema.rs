use sea_orm::entity::prelude::*;
use shared_types::ClaimSchemaId;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "proof_input_claim_schema")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub claim_schema_id: ClaimSchemaId,

    #[sea_orm(primary_key, auto_increment = false)]
    pub proof_input_schema_id: i64,

    pub order: u32,
    pub required: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::claim_schema::Entity",
        from = "Column::ClaimSchemaId",
        to = "super::claim_schema::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    ClaimSchema,
    #[sea_orm(
        belongs_to = "super::proof_input_schema::Entity",
        from = "Column::ProofInputSchemaId",
        to = "super::proof_input_schema::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    ProofInputSchema,
}

impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ClaimSchema.def()
    }
}

impl Related<super::proof_input_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofInputSchema.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
