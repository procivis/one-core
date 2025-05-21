use serde::{Deserialize, Serialize};
use shared_types::{CertificateId, IdentifierId};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateCheckFailureDTO {
    pub certificate_id: CertificateId,
    pub failure: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateCheckResultDTO {
    pub expired_certificate_ids: Vec<CertificateId>,
    pub revoked_certificate_ids: Vec<CertificateId>,
    pub check_failures: Vec<CertificateCheckFailureDTO>,
    pub deactivated_identifier_ids: Vec<IdentifierId>,
}
