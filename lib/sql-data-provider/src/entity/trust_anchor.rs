use one_core::model::trust_anchor::TrustAnchor;
use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::{DidId, OrganisationId, TrustAnchorId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "trust_anchor")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: TrustAnchorId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    #[sea_orm(column_name = "type")]
    pub type_field: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub publisher_reference: Option<String>,
    pub is_publisher: bool,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::trust_entity::Entity")]
    TrustEntity,
}

impl Related<super::trust_entity::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TrustEntity.def()
    }
}
