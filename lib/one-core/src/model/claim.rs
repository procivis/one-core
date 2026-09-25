use shared_types::ClaimId;
use time::OffsetDateTime;

use super::claim_schema::ClaimSchema;
use super::relation::Related;

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct Claim {
    pub id: ClaimId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub value: Option<String>,
    pub path: String,
    pub selectively_disclosable: bool,

    // Relations
    pub schema: Related<ClaimSchema>,
}
