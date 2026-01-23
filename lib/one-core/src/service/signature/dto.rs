use one_dto_mapper::Into;
use shared_types::{CertificateId, IdentifierId, KeyId};
use time::OffsetDateTime;

#[derive(Clone, Debug, Into)]
#[into(crate::provider::signer::dto::CreateSignatureRequest)]
pub struct CreateSignatureRequestDTO {
    #[into(skip)]
    pub issuer: IdentifierId,
    #[into(skip)]
    pub issuer_key: Option<KeyId>,
    #[into(skip)]
    pub issuer_certificate: Option<CertificateId>,
    #[into(skip)]
    pub signer: String,
    /// Signer-specific payload, each signer handles parsing individually
    pub data: serde_json::Value,
    pub validity_start: Option<OffsetDateTime>,
    pub validity_end: Option<OffsetDateTime>,
}

pub struct SignatureStatusInfo {
    pub state: SignatureState,
    pub r#type: String,
}

pub enum SignatureState {
    Active,
    Revoked,
}
