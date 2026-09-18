use std::sync::Arc;

use dto::{CertificateCheckFailureDTO, CertificateCheckResultDTO};
use serde_json::Value;
use shared_types::{CertificateId, IdentifierId};

use super::Task;
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin};
use crate::model::certificate::{
    CertificateFilterValue, CertificateListQuery, CertificateState, UpdateCertificateRequest,
};
use crate::model::identifier::{IdentifierData, IdentifierState, UpdateIdentifierRequest};
use crate::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use crate::proto::certificate_validator::{CertificateValidationOptions, CertificateValidator};
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::service::error::ServiceError;

pub mod dto;

pub struct CertificateCheck {
    certificate_repository: Arc<dyn CertificateRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
}

impl CertificateCheck {
    pub(crate) fn new(
        certificate_repository: Arc<dyn CertificateRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
    ) -> Self {
        Self {
            certificate_repository,
            identifier_repository,
            certificate_validator,
        }
    }
}

#[async_trait::async_trait]
impl Task for CertificateCheck {
    async fn run(&self, _params: Option<Value>) -> Result<Value, ServiceError> {
        let expired_certificates = self.check_expired_certificates().await?;
        let revoked_certificates = self.check_revoked_certificates().await?;

        let affected_identifier_ids: Vec<_> = expired_certificates
            .iter()
            .map(|certificate| certificate.identifier_id)
            .chain(
                revoked_certificates
                    .iter()
                    .filter(|check| check.failure.is_none())
                    .map(|certificate| certificate.identifier_id),
            )
            .collect();

        let mut deactivated_identifier_ids = vec![];
        for identifier_id in affected_identifier_ids {
            let identifier = self
                .identifier_repository
                .get(identifier_id)
                .await
                .error_while("getting identifier")?;

            let (IdentifierData::Certificate(certificates)
            | IdentifierData::CertificateAuthority(certificates)) = &identifier.data
            else {
                return Err(ServiceError::MappingError(format!(
                    "identifier {identifier_id} does not hold certificates"
                )));
            };

            if identifier.state == IdentifierState::Active
                && !certificates
                    .as_ref()
                    .await?
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
                    .await
                    .error_while("updating identifier")?;
                deactivated_identifier_ids.push(identifier_id);
            }
        }

        serde_json::to_value(CertificateCheckResultDTO {
            expired_certificate_ids: expired_certificates
                .into_iter()
                .map(|certificate| certificate.certificate_id)
                .collect(),
            revoked_certificate_ids: revoked_certificates
                .iter()
                .filter(|check| check.failure.is_none())
                .map(|certificate| certificate.certificate_id)
                .collect(),
            check_failures: revoked_certificates
                .into_iter()
                .filter_map(|check| {
                    check.failure.map(|failure| CertificateCheckFailureDTO {
                        certificate_id: check.certificate_id,
                        failure,
                    })
                })
                .collect(),
            deactivated_identifier_ids,
        })
        .map_err(|e| ServiceError::MappingError(e.to_string()))
    }
}

struct ExpirationCheckResult {
    pub certificate_id: CertificateId,
    pub identifier_id: IdentifierId,
}

struct RevocationCheckResult {
    pub certificate_id: CertificateId,
    pub identifier_id: IdentifierId,
    pub failure: Option<String>,
}

impl CertificateCheck {
    async fn check_expired_certificates(&self) -> Result<Vec<ExpirationCheckResult>, ServiceError> {
        let active_expired_certificates = self
            .certificate_repository
            .list(CertificateListQuery {
                include_count: false,
                filtering: Some(
                    CertificateFilterValue::State(CertificateState::Active).condition()
                        & CertificateFilterValue::Deleted(false)
                        & CertificateFilterValue::ExpiryDate(ValueComparison {
                            comparison: ComparisonType::LessThan,
                            value: crate::clock::now_utc(),
                        }),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting certificates")?;

        let mut expired_certificate_ids: Vec<ExpirationCheckResult> =
            Vec::with_capacity(active_expired_certificates.values.len());
        for certificate in active_expired_certificates.values {
            self.certificate_repository
                .update(
                    &certificate.id,
                    UpdateCertificateRequest {
                        state: Some(CertificateState::Expired),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating certificate")?;
            expired_certificate_ids.push(ExpirationCheckResult {
                certificate_id: certificate.id,
                identifier_id: certificate.identifier_id,
            });
        }

        Ok(expired_certificate_ids)
    }

    async fn check_revoked_certificates(&self) -> Result<Vec<RevocationCheckResult>, ServiceError> {
        let active_certificates = self
            .certificate_repository
            .list(CertificateListQuery {
                include_count: false,
                filtering: Some(
                    CertificateFilterValue::State(CertificateState::Active).condition()
                        & CertificateFilterValue::Deleted(false),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting certificates")?;

        let mut results: Vec<RevocationCheckResult> = vec![];
        for certificate in active_certificates.values {
            match self
                .certificate_validator
                .parse_pem_chain(
                    &certificate.chain,
                    CertificateValidationOptions::signature_and_revocation(None),
                )
                .await
            {
                Ok(_) => {}
                Err(error) if error.error_code() == ErrorCode::BR_0212 => {
                    results.push(RevocationCheckResult {
                        certificate_id: certificate.id,
                        identifier_id: certificate.identifier_id,
                        failure: None,
                    });

                    self.certificate_repository
                        .update(
                            &certificate.id,
                            UpdateCertificateRequest {
                                state: Some(CertificateState::Revoked),
                                ..Default::default()
                            },
                        )
                        .await
                        .error_while("updating certificate")?;
                }
                Err(err) => {
                    results.push(RevocationCheckResult {
                        certificate_id: certificate.id,
                        identifier_id: certificate.identifier_id,
                        failure: Some(err.to_string()),
                    });
                }
            };
        }

        Ok(results)
    }
}
