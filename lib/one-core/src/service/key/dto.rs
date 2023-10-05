use uuid::Uuid;

pub struct KeyRequestDTO {
    pub organisation_id: Uuid,
    pub key_type: String,
    pub key_params: serde_json::Value,
    pub name: String,
    pub storage_type: String,
    pub storage_params: serde_json::Value,
}
