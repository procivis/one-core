use shared_types::{CertificateId, KeyId, RevocationListEntryId};
use standardized_types::x509::CertificateSerial;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::provider::credential_formatter::model::CredentialStatus;

pub enum Issuer {
    Identifier {
        identifier: Box<Identifier>, // boxed because of large size difference between variants
        certificate: Option<CertificateId>,
        key: Option<KeyId>,
    },
    Key(Box<Key>), // boxed because of large size difference between variants
}

#[derive(Clone, Debug)]
pub struct CreateSignatureRequest {
    /// Signer-specific payload, each signer handles parsing individually
    pub data: serde_json::Value,
    pub validity_start: Option<OffsetDateTime>,
    pub validity_end: Option<OffsetDateTime>,
}

#[derive(Clone)]
pub struct RevocationInfo {
    pub id: RevocationListEntryId,
    pub status: CredentialStatus,
    pub serial: Option<CertificateSerial>,
}

#[derive(Clone, Debug)]
pub struct CreateSignatureResponseDTO {
    pub id: Uuid,
    pub result: String,
}
