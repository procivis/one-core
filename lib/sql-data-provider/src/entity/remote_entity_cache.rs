use one_dto_mapper::{From, Into};
use sea_orm::entity::prelude::*;
use shared_types::RemoteEntityCacheId;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "remote_entity_cache")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: RemoteEntityCacheId,

    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,

    pub key: String,
    #[sea_orm(column_type = "Blob")]
    pub value: Vec<u8>,

    pub hit_counter: u32,
    pub r#type: CacheType,

    pub media_type: Option<String>,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[derive(Clone, Debug, Eq, PartialEq, EnumIter, DeriveActiveEnum, From, Into)]
#[from(one_core::model::remote_entity_cache::CacheType)]
#[into(one_core::model::remote_entity_cache::CacheType)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "user_kind_type")]
pub enum CacheType {
    #[sea_orm(string_value = "DID_DOCUMENT")]
    DidDocument,
    #[sea_orm(string_value = "JSON_LD_CONTEXT")]
    JsonLdContext,
    #[sea_orm(string_value = "STATUSLIST_CREDENTIAL")]
    StatusListCredential,
}
