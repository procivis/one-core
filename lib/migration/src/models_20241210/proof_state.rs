use sea_orm::entity::prelude::*;
use sea_orm::sea_query;
use shared_types::ProofId;
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "proof_state")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub proof_id: ProofId,

    #[sea_orm(primary_key, auto_increment = false)]
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub state: ProofRequestState,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Iden, EnumIter, DeriveActiveEnum, Clone, Debug, Eq, PartialEq)]
#[sea_orm(
    rs_type = "String",
    db_type = "Enum",
    enum_name = "proof_request_state_enum"
)]
pub(crate) enum ProofRequestState {
    #[iden = "CREATED"]
    #[sea_orm(string_value = "CREATED")]
    Created,
    #[iden = "PENDING"]
    #[sea_orm(string_value = "PENDING")]
    Pending,
    #[iden = "REQUESTED"]
    #[sea_orm(string_value = "REQUESTED")]
    Requested,
    #[iden = "ACCEPTED"]
    #[sea_orm(string_value = "ACCEPTED")]
    Accepted,
    #[iden = "REJECTED"]
    #[sea_orm(string_value = "REJECTED")]
    Rejected,
    #[iden = "ERROR"]
    #[sea_orm(string_value = "ERROR")]
    Error,
}
