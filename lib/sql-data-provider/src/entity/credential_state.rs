use dto_mapper::From;
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

use one_core::model::credential::CredentialState as ModelCredentialState;
use one_core::model::credential::CredentialStateEnum as ModelCredentialStateEnum;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, From)]
#[convert(into = "ModelCredentialState")]
#[sea_orm(table_name = "credential_state")]
pub struct Model {
    #[convert(skip)]
    #[sea_orm(primary_key, auto_increment = false)]
    pub credential_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub created_date: OffsetDateTime,

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

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, EnumIter, DeriveActiveEnum, From)]
#[convert(from = "ModelCredentialStateEnum", into = "ModelCredentialStateEnum")]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
pub enum CredentialState {
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
    #[sea_orm(string_value = "REVOKED")]
    Revoked,
    #[sea_orm(string_value = "ERROR")]
    Error,
}
