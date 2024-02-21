use time::OffsetDateTime;
use uuid::Uuid;

use super::credential::CredentialId;

#[derive(Debug, Clone, PartialEq)]
pub struct Lvvc {
    pub id: Uuid,
    pub created_date: OffsetDateTime,
    pub credential: Vec<u8>,
    pub linked_credential_id: CredentialId,
}
