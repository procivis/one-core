use shared_types::{CertificateId, IdentifierId, KeyId};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct CreateSignatureRequestDTO {
    pub issuer: IdentifierId,
    pub issuer_key: Option<KeyId>,
    pub issuer_certificate: Option<CertificateId>,
    pub signer: String,
    /// Signer-specific payload, each signer handles parsing individually
    pub data: serde_json::Value,
}

#[derive(Clone, Debug)]
pub struct CreateSignatureResponseDTO {
    pub id: Uuid,
    pub result: String,
}
