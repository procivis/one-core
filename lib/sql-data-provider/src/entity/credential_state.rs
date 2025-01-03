use one_core::model::credential::{
    CredentialState as ModelCredentialState, CredentialStateEnum as ModelCredentialStateEnum,
};
use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use serde::Deserialize;
use shared_types::CredentialId;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Into, Deserialize)]
#[into(ModelCredentialState)]
#[sea_orm(table_name = "credential_state")]
pub struct Model {
    #[into(skip)]
    #[sea_orm(primary_key, auto_increment = false)]
    pub credential_id: CredentialId,
    #[serde(with = "time::serde::rfc3339")]
    #[sea_orm(primary_key, auto_increment = false)]
    pub created_date: OffsetDateTime,
    pub suspend_end_date: Option<OffsetDateTime>,

    pub state: CredentialState,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::credential::Entity",
        from = "Column::CredentialId",
        to = "super::credential::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Credential,
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

#[derive(
    Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From, Deserialize,
)]
#[from(ModelCredentialStateEnum)]
#[into(ModelCredentialStateEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
#[serde(rename_all = "UPPERCASE")]
pub enum CredentialState {
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
    #[sea_orm(string_value = "REVOKED")]
    Revoked,
    #[sea_orm(string_value = "SUSPENDED")]
    Suspended,
    #[sea_orm(string_value = "ERROR")]
    Error,
}
