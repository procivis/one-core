use shared_types::{CertificateId, IdentifierId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::CertificateService;
use super::dto::{CertificateResponseDTO, CreateCertificateRequestDTO};
use super::mapper::create_response_dto;
use super::validator::ParsedCertificate;
use crate::model::certificate::{Certificate, CertificateRelations, CertificateState};
use crate::service::error::{EntityNotFoundError, ServiceError, ValidationError};

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

        let ParsedCertificate { attributes, .. } = self
            .validator
            .parse_pem_chain(certificate.chain.as_bytes(), false, None)
            .await?;

        Ok(create_response_dto(certificate, attributes))
    }

    pub(crate) async fn validate_and_prepare_certificate(
        &self,
        identifier_id: IdentifierId,
        request: CreateCertificateRequestDTO,
    ) -> Result<Certificate, ServiceError> {
        let key = self
            .key_repository
            .get_key(&request.key_id, &Default::default())
            .await?
            .ok_or(EntityNotFoundError::Key(request.key_id))?;

        let ParsedCertificate {
            attributes,
            subject_common_name,
            ..
        } = self
            .validator
            .parse_pem_chain(request.chain.as_bytes(), true, Some(&key))
            .await?;

        let name = match request.name {
            Some(name) => name,
            None => subject_common_name.ok_or_else(|| {
                ValidationError::CertificateParsingFailed("missing common-name".to_string())
            })?,
        };
        Ok(Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            expiry_date: attributes.not_after,
            name,
            chain: request.chain,
            state: CertificateState::Active,
            key: Some(key),
            organisation: None,
        })
    }
}
