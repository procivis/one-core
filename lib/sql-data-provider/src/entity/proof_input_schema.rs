use sea_orm::entity::prelude::*;
use shared_types::{CredentialSchemaId, ProofSchemaId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "proof_input_schema")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub order: i32,
    pub validity_constraint: Option<i64>,
    pub credential_schema: CredentialSchemaId,
    pub proof_schema: ProofSchemaId,
}

#[expect(clippy::enum_variant_names)]
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::credential_schema::Entity",
        from = "Column::CredentialSchema",
        to = "super::credential_schema::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    CredentialSchema,
    #[sea_orm(has_many = "super::proof_input_claim_schema::Entity")]
    ProofInputClaimSchema,
    #[sea_orm(
        belongs_to = "super::proof_schema::Entity",
        from = "Column::ProofSchema",
        to = "super::proof_schema::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    ProofSchema,
}

impl Related<super::credential_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialSchema.def()
    }
}

impl Related<super::proof_input_claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofInputClaimSchema.def()
    }
}

impl Related<super::proof_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofSchema.def()
    }
}

impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        super::proof_input_claim_schema::Relation::ClaimSchema.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::proof_input_claim_schema::Relation::ProofInputSchema
                .def()
                .rev(),
        )
    }
}

impl ActiveModelBehavior for ActiveModel {}
