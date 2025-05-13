use serde::{Deserialize, Serialize};
use shared_types::{CertificateId, IdentifierId};
use time::OffsetDateTime;

use super::key::{Key, KeyRelations};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    pub id: CertificateId,
    pub identifier_id: IdentifierId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiry_date: OffsetDateTime,
    pub name: String,
    pub chain: String,
    pub state: CertificateState,

    // Relations:
    pub key: Option<Key>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateState {
    NotYetActive,
    Active,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CertificateRelations {
    pub key: Option<KeyRelations>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateCertificateRequest {
    pub name: Option<String>,
    pub state: Option<CertificateState>,
}
