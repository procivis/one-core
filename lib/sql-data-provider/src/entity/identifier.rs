use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::{DidId, EntityId, IdentifierId, KeyId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "identifier")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: IdentifierId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    #[sea_orm(column_name = "type")]
    pub r#type: IdentifierType,
    pub is_remote: bool,
    pub status: IdentifierStatus,
    pub organisation_id: Option<OrganisationId>,
    pub did_id: Option<DidId>,
    pub key_id: Option<KeyId>,
    pub deleted_at: Option<OffsetDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::organisation::Entity",
        from = "Column::OrganisationId",
        to = "super::organisation::Column::Id"
    )]
    Organisation,
    #[sea_orm(
        belongs_to = "super::did::Entity",
        from = "Column::DidId",
        to = "super::did::Column::Id"
    )]
    Did,
    #[sea_orm(
        belongs_to = "super::key::Entity",
        from = "Column::KeyId",
        to = "super::key::Column::Id"
    )]
    Key,
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
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

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, From, Into)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
#[from(one_core::model::identifier::IdentifierType)]
#[into(one_core::model::identifier::IdentifierType)]
pub enum IdentifierType {
    #[sea_orm(string_value = "DID")]
    Did,
    #[sea_orm(string_value = "KEY")]
    Key,
    #[sea_orm(string_value = "CERTIFICATE")]
    Certificate,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum, From, Into)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
#[from(one_core::model::identifier::IdentifierStatus)]
#[into(one_core::model::identifier::IdentifierStatus)]
pub enum IdentifierStatus {
    #[sea_orm(string_value = "ACTIVE")]
    Active,
    #[sea_orm(string_value = "DEACTIVATED")]
    Deactivated,
}
