use shared_types::CertificateId;

use super::CertificateService;
use super::dto::CertificateResponseDTO;
use crate::model::certificate::CertificateRelations;
use crate::service::error::{EntityNotFoundError, ServiceError};
use crate::validator::throw_if_org_not_matching_session;

impl CertificateService {
    pub async fn get_certificate(
        &self,
        id: CertificateId,
    ) -> Result<CertificateResponseDTO, ServiceError> {
        let certificate = self
            .certificate_repository
            .get(
                id,
                &CertificateRelations {
                    key: Some(Default::default()),
                    organisation: Some(Default::default()),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Certificate(id))?;

        throw_if_org_not_matching_session(
            certificate
                .organisation_id
                .as_ref()
                .ok_or(ServiceError::MappingError(format!(
                    "missing organisation on certificate {}",
                    certificate.id
                )))?,
            &*self.session_provider,
        )?;

        Ok(certificate.try_into()?)
    }
}
