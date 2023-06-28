use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "proof_schema_claim")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub claim_schema_id: String,

    #[sea_orm(primary_key, auto_increment = false)]
    pub proof_schema_id: String,

    pub is_required: bool,
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
        belongs_to = "super::proof_schema::Entity",
        from = "Column::ProofSchemaId",
        to = "super::proof_schema::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    ProofSchema,
}

impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ClaimSchema.def()
    }
}

impl Related<super::proof_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofSchema.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
