use dto_mapper::Into;
use shared_types::ClaimSchemaId;
use time::OffsetDateTime;

#[derive(Clone, Debug, Eq, PartialEq, Into)]
#[into(one_providers::common_models::claim_schema::ClaimSchema)]
pub struct ClaimSchema {
    pub id: ClaimSchemaId,
    pub key: String,
    pub data_type: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub array: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ClaimSchemaRelations {}
