use dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::JsonLdContextId;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "json_ld_context")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: JsonLdContextId,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    #[sea_orm(column_type = "Binary(BlobSize::Long)")]
    pub context: Vec<u8>,

    pub url: String,
    pub hit_counter: u32,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
