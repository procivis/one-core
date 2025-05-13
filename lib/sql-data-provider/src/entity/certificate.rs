use one_core::model::certificate::CertificateState as ModelCertificateState;
use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use shared_types::{CertificateId, IdentifierId, KeyId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "certificate")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: CertificateId,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiry_date: OffsetDateTime,

    pub name: String,
    pub chain: String,
    pub state: CertificateState,

    pub identifier_id: IdentifierId,
    pub key_id: Option<KeyId>,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::identifier::Entity",
        from = "Column::IdentifierId",
        to = "super::identifier::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Identifier,
    #[sea_orm(
        belongs_to = "super::key::Entity",
        from = "Column::KeyId",
        to = "super::key::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Key,
}

impl Related<super::key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Key.def()
    }
}

impl Related<super::identifier::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Identifier.def()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(ModelCertificateState)]
#[into(ModelCertificateState)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum CertificateState {
    #[sea_orm(string_value = "NOT_YET_ACTIVE")]
    NotYetActive,
    #[sea_orm(string_value = "ACTIVE")]
    Active,
    #[sea_orm(string_value = "REVOKED")]
    Revoked,
    #[sea_orm(string_value = "EXPIRED")]
    Expired,
}
