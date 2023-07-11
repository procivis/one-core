use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "proof_state")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub proof_id: String,

    #[sea_orm(primary_key, auto_increment = false)]
    pub created_date: OffsetDateTime,

    pub last_modified: OffsetDateTime,
    pub state: ProofRequestState,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::proof::Entity",
        from = "Column::ProofId",
        to = "super::proof::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Proof,
}

impl Related<super::proof::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Proof.def()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
pub enum ProofRequestState {
    #[default]
    #[sea_orm(string_value = "CREATED")]
    Created,
    #[sea_orm(string_value = "PENDING")]
    Pending,
    #[sea_orm(string_value = "OFFERED")]
    Offered,
    #[sea_orm(string_value = "ACCEPTED")]
    Accepted,
    #[sea_orm(string_value = "REJECTED")]
    Rejected,
    #[sea_orm(string_value = "ERROR")]
    Error,
}
