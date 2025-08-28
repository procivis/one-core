use one_core::model::history::{
    HistoryAction as ModelHistoryAction, HistoryEntityType as ModelHistoryEntityType,
};
use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::{EntityId, HistoryId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "history")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: HistoryId,
    pub created_date: OffsetDateTime,
    pub action: HistoryAction,
    pub entity_id: Option<EntityId>,
    pub entity_type: HistoryEntityType,
    pub metadata: Option<String>,
    pub name: String,
    pub target: Option<String>,

    pub organisation_id: Option<OrganisationId>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::organisation::Entity",
        from = "Column::OrganisationId",
        to = "super::organisation::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Organisation,

    // event related entities
    #[sea_orm(
        belongs_to = "super::credential::Entity",
        from = "Column::EntityId",
        to = "super::credential::Column::Id"
    )]
    MentionedCredential,
    #[sea_orm(
        belongs_to = "super::proof::Entity",
        from = "Column::EntityId",
        to = "super::proof::Column::Id"
    )]
    MentionedProof,
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, From, Into)]
#[from(ModelHistoryAction)]
#[into(ModelHistoryAction)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum HistoryAction {
    #[sea_orm(string_value = "ACCEPTED")]
    Accepted,
    #[sea_orm(string_value = "CREATED")]
    Created,
    #[sea_orm(string_value = "CSR_GENERATED")]
    CsrGenerated,
    #[sea_orm(string_value = "DEACTIVATED")]
    Deactivated,
    #[sea_orm(string_value = "DELETED")]
    Deleted,
    #[sea_orm(string_value = "ERRORED")]
    Errored,
    #[sea_orm(string_value = "ISSUED")]
    Issued,
    #[sea_orm(string_value = "OFFERED")]
    Offered,
    #[sea_orm(string_value = "REJECTED")]
    Rejected,
    #[sea_orm(string_value = "REQUESTED")]
    Requested,
    #[sea_orm(string_value = "REVOKED")]
    Revoked,
    #[sea_orm(string_value = "PENDING")]
    Pending,
    #[sea_orm(string_value = "SUSPENDED")]
    Suspended,
    #[sea_orm(string_value = "RESTORED")]
    Restored,
    #[sea_orm(string_value = "SHARED")]
    Shared,
    #[sea_orm(string_value = "IMPORTED")]
    Imported,
    #[sea_orm(string_value = "CLAIMS_REMOVED")]
    ClaimsRemoved,
    #[sea_orm(string_value = "ACTIVATED")]
    Activated,
    #[sea_orm(string_value = "WITHDRAWN")]
    Withdrawn,
    #[sea_orm(string_value = "REMOVED")]
    Removed,
    #[sea_orm(string_value = "RETRACTED")]
    Retracted,
    #[sea_orm(string_value = "UPDATED")]
    Updated,
    #[sea_orm(string_value = "REACTIVATED")]
    Reactivated,
    #[sea_orm(string_value = "EXPIRED")]
    Expired,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, From, Into)]
#[from(ModelHistoryEntityType)]
#[into(ModelHistoryEntityType)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum HistoryEntityType {
    #[sea_orm(string_value = "KEY")]
    Key,
    #[sea_orm(string_value = "DID")]
    Did,
    #[sea_orm(string_value = "CERTIFICATE")]
    Certificate,
    #[sea_orm(string_value = "IDENTIFIER")]
    Identifier,
    #[sea_orm(string_value = "CREDENTIAL")]
    Credential,
    #[sea_orm(string_value = "CREDENTIAL_SCHEMA")]
    CredentialSchema,
    #[sea_orm(string_value = "PROOF")]
    Proof,
    #[sea_orm(string_value = "PROOF_SCHEMA")]
    ProofSchema,
    #[sea_orm(string_value = "ORGANISATION")]
    Organisation,
    #[sea_orm(string_value = "BACKUP")]
    Backup,
    #[sea_orm(string_value = "TRUST_ANCHOR")]
    TrustAnchor,
    #[sea_orm(string_value = "TRUST_ENTITY")]
    TrustEntity,
    #[sea_orm(string_value = "WALLET_UNIT")]
    WalletUnit,
    #[sea_orm(string_value = "WALLET_UNIT_ATTESTATION")]
    WalletUnitAttestation,
}
