use sea_orm::entity::prelude::*;
use shared_types::{KeyId, OrganisationId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "key")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: KeyId,

    pub created_date: OffsetDateTime,

    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,

    pub name: String,

    #[sea_orm(column_type = "Blob")]
    pub public_key: Vec<u8>,

    #[sea_orm(column_type = "Blob")]
    pub key_reference: Vec<u8>,

    pub storage_type: String,
    pub key_type: String,

    pub organisation_id: OrganisationId,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::credential::Entity")]
    Credential,
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

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl Related<super::key_did::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::KeyDid.def()
    }
}

impl Related<super::did::Entity> for Entity {
    fn to() -> RelationDef {
        super::key_did::Relation::Did.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::key_did::Relation::Key.def().rev())
    }
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}
