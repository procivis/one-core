use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::{CredentialId, DidId, IdentifierId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "revocation_list_entry")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub created_date: OffsetDateTime,
    pub revocation_list_id: String,
    pub index: u32,
    pub credential_id: Option<CredentialId>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::revocation_list::Entity",
        from = "Column::RevocationListId",
        to = "super::revocation_list::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    RevocationList,
    #[sea_orm(
        belongs_to = "super::credential::Entity",
        from = "Column::CredentialId",
        to = "super::credential::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Credential,
}

impl Related<super::revocation_list::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::RevocationList.def()
    }
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
