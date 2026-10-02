use shared_types::CertificateId;

use super::dto::EntityIdsResponseRestDTO;

impl From<Vec<CertificateId>> for EntityIdsResponseRestDTO {
    fn from(ids: Vec<CertificateId>) -> Self {
        Self { ids }
    }
}
