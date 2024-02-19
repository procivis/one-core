use sea_orm::entity::prelude::*;
use shared_types::DidId;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "proof")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub transport: String,
    pub redirect_uri: Option<String>,

    pub verifier_did_id: Option<DidId>,
    pub holder_did_id: Option<DidId>,
    pub proof_schema_id: Option<String>,
    pub verifier_key_id: Option<String>,
    pub interaction_id: Option<String>,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::did::Entity",
        from = "Column::VerifierDidId",
        to = "super::did::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    VerifierDid,
    #[sea_orm(
        belongs_to = "super::did::Entity",
        from = "Column::HolderDidId",
        to = "super::did::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    HolderDid,
    #[sea_orm(
        belongs_to = "super::interaction::Entity",
        from = "Column::InteractionId",
        to = "super::interaction::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Interaction,
    #[sea_orm(has_many = "super::proof_claim::Entity")]
    ProofClaim,
    #[sea_orm(
        belongs_to = "super::proof_schema::Entity",
        from = "Column::ProofSchemaId",
        to = "super::proof_schema::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    ProofSchema,
    #[sea_orm(has_many = "super::proof_state::Entity")]
    ProofState,
    #[sea_orm(
        belongs_to = "super::key::Entity",
        from = "Column::VerifierKeyId",
        to = "super::key::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    VerifierKey,
}

impl Related<super::interaction::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Interaction.def()
    }
}

impl Related<super::proof_claim::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofClaim.def()
    }
}

impl Related<super::proof_schema::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofSchema.def()
    }
}

impl Related<super::proof_state::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ProofState.def()
    }
}

impl Related<super::claim::Entity> for Entity {
    fn to() -> RelationDef {
        super::proof_claim::Relation::Claim.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::proof_claim::Relation::Proof.def().rev())
    }
}
