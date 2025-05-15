use serde::{Deserialize, Serialize};
use shared_types::{CertificateId, IdentifierId};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateCheckResultDTO {
    pub expired_certificate_ids: Vec<CertificateId>,
    pub deactivated_identifier_ids: Vec<IdentifierId>,
}
