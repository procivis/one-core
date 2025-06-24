use one_core::model::proof::{ProofRole as ModelProofRole, ProofStateEnum};
use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::{CertificateId, DidId, IdentifierId, KeyId, ProofId, ProofSchemaId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "proof")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: ProofId,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub protocol: String,
    pub transport: String,
    pub redirect_uri: Option<String>,
    pub state: ProofRequestState,
    pub role: ProofRole,
    pub requested_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,

    pub verifier_identifier_id: Option<IdentifierId>,
    pub holder_identifier_id: Option<IdentifierId>,
    pub proof_schema_id: Option<ProofSchemaId>,
    pub verifier_key_id: Option<KeyId>,
    pub verifier_certificate_id: Option<CertificateId>,
    pub interaction_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(ProofStateEnum)]
#[into(ProofStateEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum ProofRequestState {
    #[sea_orm(string_value = "CREATED")]
    Created,
    #[sea_orm(string_value = "PENDING")]
    Pending,
    #[sea_orm(string_value = "REQUESTED")]
    Requested,
    #[sea_orm(string_value = "ACCEPTED")]
    Accepted,
    #[sea_orm(string_value = "REJECTED")]
    Rejected,
    #[sea_orm(string_value = "RETRACTED")]
    Retracted,
    #[sea_orm(string_value = "ERROR")]
    Error,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::identifier::Entity",
        from = "Column::VerifierIdentifierId",
        to = "super::identifier::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    VerifierIdentifier,
    #[sea_orm(
        belongs_to = "super::identifier::Entity",
        from = "Column::HolderIdentifierId",
        to = "super::identifier::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    HolderIdentifier,
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
    #[sea_orm(
        belongs_to = "super::key::Entity",
        from = "Column::VerifierKeyId",
        to = "super::key::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    VerifierKey,
    #[sea_orm(
        belongs_to = "super::certificate::Entity",
        from = "Column::VerifierCertificateId",
        to = "super::certificate::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    VerifierCertificate,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(ModelProofRole)]
#[into(ModelProofRole)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum ProofRole {
    #[sea_orm(string_value = "HOLDER")]
    Holder,
    #[sea_orm(string_value = "VERIFIER")]
    Verifier,
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

impl Related<super::claim::Entity> for Entity {
    fn to() -> RelationDef {
        super::proof_claim::Relation::Claim.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::proof_claim::Relation::Proof.def().rev())
    }
}
