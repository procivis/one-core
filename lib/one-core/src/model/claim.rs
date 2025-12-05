use shared_types::{ClaimId, CredentialId};
use time::OffsetDateTime;

use super::claim_schema::{ClaimSchema, ClaimSchemaRelations};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claim {
    pub id: ClaimId,
    pub credential_id: CredentialId, // cannot be a relation, because credential defines a reverse relation already
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub value: Option<String>,
    pub path: String,
    pub selectively_disclosable: bool,

    // Relations
    pub schema: Option<ClaimSchema>,
}

impl std::hash::Hash for Claim {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ClaimRelations {
    pub schema: Option<ClaimSchemaRelations>,
}
