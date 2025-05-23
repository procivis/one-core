use one_core::model::did::DidType as ModelDidType;
use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::{DidId, DidValue, OrganisationId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "did")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DidId,
    #[sea_orm(unique)]
    pub did: DidValue,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    #[sea_orm(column_name = "type")]
    pub type_field: DidType,
    pub method: String,
    pub log: Option<String>,
    pub organisation_id: Option<OrganisationId>,
    pub deactivated: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::key_did::Entity")]
    KeyDid,
    #[sea_orm(
        belongs_to = "super::organisation::Entity",
        from = "Column::OrganisationId",
        to = "super::organisation::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Organisation,
}

impl Related<super::key_did::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::KeyDid.def()
    }
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl Related<super::key::Entity> for Entity {
    fn to() -> RelationDef {
        super::key_did::Relation::Key.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::key_did::Relation::Did.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[from(ModelDidType)]
#[into(ModelDidType)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum DidType {
    #[sea_orm(string_value = "REMOTE")]
    Remote,
    #[sea_orm(string_value = "LOCAL")]
    Local,
}
