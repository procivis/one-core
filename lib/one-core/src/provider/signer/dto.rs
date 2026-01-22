use shared_types::{CertificateId, IdentifierId, KeyId, RevocationListEntryId};
use standardized_types::x509::CertificateSerial;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::provider::credential_formatter::model::CredentialStatus;

#[derive(Clone, Debug)]
pub struct CreateSignatureRequestDTO {
    pub issuer: IdentifierId,
    pub issuer_key: Option<KeyId>,
    pub issuer_certificate: Option<CertificateId>,
    pub signer: String,
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
