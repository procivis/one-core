use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use serde::Deserialize;
use shared_types::{IdentifierId, TrustEntryId, TrustListPublicationId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "trust_entry")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: TrustEntryId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub status: TrustEntryState,
    #[sea_orm(column_type = "Blob")]
    pub metadata: Vec<u8>,
    pub trust_list_publication_id: TrustListPublicationId,
    #[sea_orm(nullable)]
    pub identifier_id: Option<IdentifierId>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::trust_list_publication::Entity",
        from = "Column::TrustListPublicationId",
        to = "super::trust_list_publication::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    TrustListPublication,
    #[sea_orm(
        belongs_to = "super::identifier::Entity",
        from = "Column::IdentifierId",
        to = "super::identifier::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Identifier,
}

impl Related<super::trust_list_publication::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TrustListPublication.def()
    }
}

impl Related<super::identifier::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Identifier.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, From, Into, Deserialize)]
#[into(one_core::model::trust_entry::TrustEntryState)]
#[from(one_core::model::trust_entry::TrustEntryState)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)")]
pub enum TrustEntryState {
    #[sea_orm(string_value = "ACTIVE")]
    Active,
    #[sea_orm(string_value = "SUSPENDED")]
    Suspended,
    #[sea_orm(string_value = "REMOVED")]
    Removed,
}
