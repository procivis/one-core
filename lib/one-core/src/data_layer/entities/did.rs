use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "did")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,

    pub did: String,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    #[sea_orm(column_name = "type")]
    pub type_field: DidType,
    pub method: DidMethod,

    pub organisation_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::key::Entity")]
    Key,
    #[sea_orm(
        belongs_to = "super::organisation::Entity",
        from = "Column::OrganisationId",
        to = "super::organisation::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Organisation,
}

impl Related<super::key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Key.def()
    }
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        super::key::Relation::Credential.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::key::Relation::Did.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Clone, Debug, Default, Eq, PartialEq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
pub enum DidType {
    #[default]
    #[sea_orm(string_value = "REMOTE")]
    Remote,
    #[sea_orm(string_value = "LOCAL")]
    Local,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
pub enum DidMethod {
    #[default]
    #[sea_orm(string_value = "KEY")]
    Key,
    #[sea_orm(string_value = "WEB")]
    Web,
}
