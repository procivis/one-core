use shared_types::{CertificateId, IdentifierId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::CertificateService;
use super::dto::{CertificateResponseDTO, CreateCertificateRequestDTO};
use super::validator::ParsedCertificate;
use crate::model::certificate::{
    Certificate, CertificateFilterValue, CertificateListQuery, CertificateRelations,
    CertificateState,
};
use crate::model::key::Key;
use crate::model::list_filter::ListFilterCondition;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, ServiceError, ValidationError,
};

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

        Ok(certificate.try_into()?)
    }

    pub(crate) async fn validate_and_prepare_certificate(
        &self,
        identifier_id: IdentifierId,
        organisation_id: OrganisationId,
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
            public_key,
            ..
        } = self
            .validator
            .parse_pem_chain(request.chain.as_bytes(), true)
            .await?;

        validate_subject_public_key(&public_key, &key)?;

        let name = match request.name {
            Some(name) => name,
            None => subject_common_name.ok_or_else(|| {
                ValidationError::CertificateParsingFailed("missing common-name".to_string())
            })?,
        };

        if self
            .certificate_repository
            .list(CertificateListQuery {
                filtering: Some(ListFilterCondition::Value(
                    CertificateFilterValue::Fingerprint(attributes.fingerprint.clone()),
                )),
                ..Default::default()
            })
            .await?
            .total_items
            > 0
        {
            return Err(BusinessLogicError::CertificateAlreadyExists.into());
        };

        Ok(Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            organisation_id: Some(organisation_id),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            expiry_date: attributes.not_after,
            name,
            chain: request.chain,
            fingerprint: attributes.fingerprint,
            state: CertificateState::Active,
            key: Some(key),
        })
    }
}

fn validate_subject_public_key(
    subject_public_key: &KeyHandle,
    expected_key: &Key,
) -> Result<(), ServiceError> {
    let subject_raw_public_key = subject_public_key.public_key_as_raw();
    if expected_key.public_key != subject_raw_public_key {
        return Err(ValidationError::CertificateKeyNotMatching.into());
    }

    Ok(())
}
