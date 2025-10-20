use std::sync::Arc;

use uuid::Uuid;

use crate::model::certificate::{Certificate, CertificateState};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::repository::certificate_repository::MockCertificateRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::service::certificate::CertificateService;
use crate::service::error::{ServiceError, ValidationError};
use crate::service::test_utilities::get_dummy_date;

#[tokio::test]
async fn test_get_cert_fail_session_org_mismatch() {
    let mut cert_repo = MockCertificateRepository::new();
    cert_repo.expect_get().returning(|_, _| {
        Ok(Some(Certificate {
            id: Uuid::new_v4().into(),
            identifier_id: Uuid::new_v4().into(),
            organisation_id: Some(Uuid::new_v4().into()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            expiry_date: get_dummy_date(),
            name: "".to_string(),
            chain: "".to_string(),
            fingerprint: "".to_string(),
            state: CertificateState::NotYetActive,
            key: None,
        }))
    });
    let service = CertificateService {
        certificate_repository: Arc::new(cert_repo),
        key_repository: Arc::new(MockKeyRepository::new()),
        validator: Arc::new(MockCertificateValidator::new()),
        session_provider: Arc::new(StaticSessionProvider::new_random()),
    };

    let result = service.get_certificate(Uuid::new_v4().into()).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}
