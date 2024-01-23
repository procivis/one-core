use time::OffsetDateTime;
use uuid::Uuid;

use dto_mapper::From;

use crate::model::{
    common::{GetListQueryParams, GetListResponse},
    key::{Key, SortableKeyColumn},
};

pub struct KeyRequestDTO {
    pub organisation_id: Uuid,
    pub key_type: String,
    pub key_params: serde_json::Value,
    pub name: String,
    pub storage_type: String,
    pub storage_params: serde_json::Value,
}

pub struct KeyResponseDTO {
    pub id: Uuid,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub organisation_id: Uuid,
    pub name: String,
    pub public_key: Vec<u8>,
    pub key_type: String,
    pub storage_type: String,
}

#[derive(Clone, Debug, From)]
#[from(Key)]
pub struct KeyListItemResponseDTO {
    pub id: Uuid,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub public_key: Vec<u8>,
    pub key_type: String,
    pub storage_type: String,
}

pub type GetKeyListResponseDTO = GetListResponse<KeyListItemResponseDTO>;
pub type GetKeyQueryDTO = GetListQueryParams<SortableKeyColumn>;
