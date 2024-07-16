use one_providers::common_models::key::Key;
use serde::{Deserialize, Serialize};
use shared_types::OrganisationId;
use time::OffsetDateTime;
use uuid::Uuid;

use dto_mapper::From;

use crate::model::common::{GetListQueryParams, GetListResponse};
use crate::model::key::SortableKeyColumn;

pub struct KeyRequestDTO {
    pub organisation_id: OrganisationId,
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
    pub organisation_id: OrganisationId,
    pub name: String,
    pub public_key: Vec<u8>,
    pub key_type: String,
    pub storage_type: String,
}

#[derive(Clone, Debug, From, Serialize, Deserialize)]
#[from(Key)]
pub struct KeyListItemResponseDTO {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub public_key: Vec<u8>,
    pub key_type: String,
    pub storage_type: String,
}

pub type GetKeyListResponseDTO = GetListResponse<KeyListItemResponseDTO>;
pub type GetKeyQueryDTO = GetListQueryParams<SortableKeyColumn>;

#[derive(Debug)]
pub struct KeyGenerateCSRRequestDTO {
    pub profile: KeyGenerateCSRRequestProfile,
    pub not_before: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub subject: KeyGenerateCSRRequestSubjectDTO,
}

#[derive(Debug)]
pub enum KeyGenerateCSRRequestProfile {
    Mdl,
}

#[derive(Debug)]
pub struct KeyGenerateCSRRequestSubjectDTO {
    pub country_name: String,
    pub common_name: String,

    pub state_or_province_name: Option<String>,
    pub organisation_name: Option<String>,
    pub locality_name: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug)]
pub struct KeyGenerateCSRResponseDTO {
    pub content: String,
}
