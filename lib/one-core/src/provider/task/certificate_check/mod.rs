use std::collections::HashSet;
use std::sync::Arc;

use dto::CertificateCheckResultDTO;
use serde_json::Value;
use shared_types::{CertificateId, IdentifierId};
use time::OffsetDateTime;

use super::Task;
use crate::model::certificate::{
    CertificateFilterValue, CertificateListQuery, CertificateState, UpdateCertificateRequest,
};
use crate::model::identifier::{IdentifierRelations, IdentifierState, UpdateIdentifierRequest};
use crate::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::service::error::{EntityNotFoundError, ServiceError};

pub mod dto;

pub struct CertificateCheck {
    certificate_repository: Arc<dyn CertificateRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
}

impl CertificateCheck {
    pub fn new(
        certificate_repository: Arc<dyn CertificateRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
    ) -> Self {
        Self {
            certificate_repository,
            identifier_repository,
        }
    }
}

#[async_trait::async_trait]
impl Task for CertificateCheck {
    async fn run(&self) -> Result<Value, ServiceError> {
        let active_expired_certificates = self
            .certificate_repository
            .list(CertificateListQuery {
                filtering: Some(
                    CertificateFilterValue::State(CertificateState::Active).condition()
                        & CertificateFilterValue::ExpiryDate(ValueComparison {
                            comparison: ComparisonType::LessThan,
                            value: OffsetDateTime::now_utc(),
                        }),
                ),
                ..Default::default()
            })
            .await?;

        let mut affected_identifier_ids: HashSet<IdentifierId> = HashSet::new();
        let mut expired_certificate_ids: Vec<CertificateId> =
            Vec::with_capacity(active_expired_certificates.total_items as usize);
        for certificate in active_expired_certificates.values {
            self.certificate_repository
                .update(
                    &certificate.id,
                    UpdateCertificateRequest {
                        state: Some(CertificateState::Expired),
                        ..Default::default()
                    },
                )
                .await?;
            expired_certificate_ids.push(certificate.id);
            affected_identifier_ids.insert(certificate.identifier_id);
        }

        let mut deactivated_identifier_ids = vec![];
        for identifier_id in affected_identifier_ids {
            let identifier = self
                .identifier_repository
                .get(
                    identifier_id,
                    &IdentifierRelations {
                        certificates: Some(Default::default()),
                        ..Default::default()
                    },
                )
                .await?
                .ok_or(EntityNotFoundError::Identifier(identifier_id))?;

            if identifier.state == IdentifierState::Active
                && !identifier
                    .certificates
                    .ok_or(ServiceError::MappingError(
                        "certificates missing".to_string(),
                    ))?
                    .iter()
                    .any(|certificate| certificate.state == CertificateState::Active)
            {
                self.identifier_repository
                    .update(
                        &identifier_id,
                        UpdateIdentifierRequest {
                            state: Some(IdentifierState::Deactivated),
                            ..Default::default()
                        },
                    )
                    .await?;
                deactivated_identifier_ids.push(identifier_id);
            }
        }

        serde_json::to_value(CertificateCheckResultDTO {
            expired_certificate_ids,
            deactivated_identifier_ids,
        })
        .map_err(|e| ServiceError::MappingError(e.to_string()))
    }
}
