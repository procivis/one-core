use time::OffsetDateTime;
use uuid::Uuid;

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
    pub public_key: String,
    pub key_type: String,
    pub storage_type: String,
}
