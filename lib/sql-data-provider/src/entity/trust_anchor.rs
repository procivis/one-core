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
    pub publisher_reference: Option<String>,
    pub role: TrustAnchorRole,
    pub priority: Option<u32>,
    pub organisation_id: OrganisationId,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::organisation::Entity",
        from = "Column::OrganisationId",
        to = "super::organisation::Column::Id",
        on_update = "Restrict",
        on_delete = "Restrict"
    )]
    Organisation,
}

impl Related<super::organisation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Organisation.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, Into, From)]
#[into(one_core::model::trust_anchor::TrustAnchorRole)]
#[from(one_core::model::trust_anchor::TrustAnchorRole)]
#[sea_orm(
    rs_type = "String",
    db_type = "Enum",
    enum_name = "trust_anchor_role_enum"
)]
pub enum TrustAnchorRole {
    #[sea_orm(string_value = "CLIENT")]
    Client,
    #[sea_orm(string_value = "PUBLISHER")]
    Publisher,
}
