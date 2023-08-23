use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "claim")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub claim_schema_id: String,
    pub value: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}

impl ActiveModelBehavior for ActiveModel {}

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
    #[sea_orm(has_one = "super::credential_claim::Entity")]
    CredentialClaim,
    #[sea_orm(has_one = "super::proof_claim::Entity")]
    ProofClaim,
}

impl Related<super::claim_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ClaimSchema.def()
    }
}

impl Related<super::proof_claim::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofClaim.def()
    }
}

impl Related<super::credential_claim::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialClaim.def()
    }
}

impl Related<super::proof::Entity> for Entity {
    fn to() -> RelationDef {
        super::proof_claim::Relation::Proof.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::proof_claim::Relation::Claim.def().rev())
    }
}
