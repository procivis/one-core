use time::OffsetDateTime;
use uuid::Uuid;

use super::claim_schema::{ClaimSchema, ClaimSchemaRelations};

pub type ClaimId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim {
    pub id: ClaimId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub value: String,

    // Relations
    pub schema: Option<ClaimSchema>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ClaimRelations {
    pub schema: Option<ClaimSchemaRelations>,
}
