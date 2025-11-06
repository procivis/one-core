use shared_types::BlobId;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Blob {
    pub id: BlobId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub value: Vec<u8>,
    pub r#type: BlobType,
}

impl Blob {
    pub fn new(value: impl Into<Vec<u8>>, r#type: BlobType) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            value: value.into(),
            r#type,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateBlobRequest {
    pub value: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobType {
    Credential,
    Proof,
    WalletAppAttestation,
}
