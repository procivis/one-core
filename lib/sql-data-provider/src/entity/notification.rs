use one_core::model::trust_entity::TrustEntity;
use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use serde::Deserialize;
use shared_types::{NotificationId, OrganisationId, TaskId};
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "notification")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: NotificationId,
    #[sea_orm(column_type = "Text")]
    pub url: String,
    #[sea_orm(column_type = "Blob")]
    pub payload: Vec<u8>,
    pub created_date: OffsetDateTime,
    pub next_try_date: OffsetDateTime,
    pub tries_count: u32,
    #[sea_orm(column_name = "type")]
    pub r#type: TaskId,
    pub history_target: Option<String>,
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
