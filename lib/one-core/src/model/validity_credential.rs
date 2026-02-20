use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub struct Mdoc {
    pub id: Uuid,
    pub created_date: OffsetDateTime,
    pub credential: Vec<u8>,
    pub linked_credential_id: CredentialId,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidityCredential {
    pub id: Uuid,
    pub created_date: OffsetDateTime,
    pub credential: Vec<u8>,
    pub linked_credential_id: CredentialId,
    pub r#type: ValidityCredentialType,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ValidityCredentialType {
    Mdoc,
}

impl From<Mdoc> for ValidityCredential {
    fn from(value: Mdoc) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            credential: value.credential,
            linked_credential_id: value.linked_credential_id,
            r#type: ValidityCredentialType::Mdoc,
        }
    }
}
