use time::OffsetDateTime;
use uuid::Uuid;

pub type ClaimSchemaId = Uuid;

#[derive(Clone)]
pub struct ClaimSchema {
    pub id: ClaimSchemaId,
    pub key: String,
    pub data_type: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
}

pub struct ClaimSchemaRelations {}
