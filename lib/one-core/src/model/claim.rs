use dto_mapper::{convert_inner, Into};
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::claim_schema::{ClaimSchema, ClaimSchemaRelations};

pub type ClaimId = Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Into)]
#[into(one_providers::common_models::claim::Claim)]
pub struct Claim {
    pub id: ClaimId,
    pub credential_id: CredentialId, // cannot be a relation, because credential defines a reverse relation already
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub value: String,
    pub path: String,

    // Relations
    #[into(with_fn = "convert_inner")]
    pub schema: Option<ClaimSchema>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ClaimRelations {
    pub schema: Option<ClaimSchemaRelations>,
}
