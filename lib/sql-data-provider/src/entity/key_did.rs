use dto_mapper::From;
use sea_orm::entity::prelude::*;

use one_core::model::did::KeyRole as ModelKeyRole;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "key_did")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub did_id: String,

    #[sea_orm(primary_key)]
    pub key_id: String,

    #[sea_orm(primary_key)]
    pub role: KeyRole,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::did::Entity",
        from = "Column::DidId",
        to = "super::did::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Did,
    #[sea_orm(
        belongs_to = "super::key::Entity",
        from = "Column::KeyId",
        to = "super::key::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Key,
}

impl Related<super::did::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Did.def()
    }
}

impl Related<super::key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Key.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Clone, Debug, Default, Eq, PartialEq, EnumIter, DeriveActiveEnum, From)]
#[convert(from = "ModelKeyRole", into = "ModelKeyRole")]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
pub enum KeyRole {
    #[default]
    #[sea_orm(string_value = "AUTHENTICATION")]
    Authentication,
    #[sea_orm(string_value = "ASSERTION_METHOD")]
    AssertionMethod,
    #[sea_orm(string_value = "KEY_AGREEMENT")]
    KeyAgreement,
    #[sea_orm(string_value = "CAPABILITY_INVOCATION")]
    CapabilityInvocation,
    #[sea_orm(string_value = "CAPABILITY_DELEGATION")]
    CapabilityDelegation,
}
