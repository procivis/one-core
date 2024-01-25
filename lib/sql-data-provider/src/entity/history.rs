use dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use one_core::model::history::HistoryAction as ModelHistoryAction;
use one_core::model::history::HistoryEntityType as ModelHistoryEntityType;
use shared_types::{EntityId, HistoryId, OrganisationId};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "history")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: HistoryId,
    pub created_date: OffsetDateTime,
    pub action: HistoryAction,
    pub entity_id: EntityId,
    pub entity_type: HistoryEntityType,

    pub organisation_id: OrganisationId,
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
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
pub enum HistoryAction {
    #[sea_orm(string_value = "ACCEPTED")]
    Accepted,
    #[sea_orm(string_value = "CREATED")]
    Created,
    #[sea_orm(string_value = "DEACTIVATED")]
    Deactivated,
    #[sea_orm(string_value = "DELETED")]
    Deleted,
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
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, From, Into)]
#[from(ModelHistoryEntityType)]
#[into(ModelHistoryEntityType)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
pub enum HistoryEntityType {
    #[sea_orm(string_value = "KEY")]
    Key,
    #[sea_orm(string_value = "DID")]
    Did,
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
}
