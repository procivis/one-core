use shared_types::ClaimSchemaId;
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimSchema {
    pub id: ClaimSchemaId,
    pub key: String,
    pub data_type: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub array: bool,
    pub metadata: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ClaimSchemaRelations {}
