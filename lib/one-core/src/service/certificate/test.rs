use std::sync::Arc;

use uuid::Uuid;

use crate::model::certificate::{Certificate, CertificateState};
use crate::model::identifier::{Identifier, IdentifierType};
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::repository::certificate_repository::MockCertificateRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::service::certificate::CertificateService;
use crate::service::error::{EntityNotFoundError, ServiceError, ValidationError};
use crate::service::test_utilities::{dummy_identifier, get_dummy_date};

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
        identifier_repository: Arc::new(MockIdentifierRepository::new()),
        session_provider: Arc::new(StaticSessionProvider::new_random()),
    };

    let result = service.get_certificate(Uuid::new_v4().into()).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}

#[tokio::test]
async fn test_get_certificate_authority_invalid_identifier() {
    let id = Uuid::new_v4().into();

    let mut certificate_repository = MockCertificateRepository::new();
    certificate_repository.expect_get().returning(|id, _| {
        Ok(Some(Certificate {
            id,
            identifier_id: Uuid::new_v4().into(),
            organisation_id: Some(Uuid::new_v4().into()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            expiry_date: get_dummy_date(),
            name: "".to_string(),
            chain: "".to_string(),
            fingerprint: "".to_string(),
            state: CertificateState::Active,
            key: None,
        }))
    });

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().returning(|_, _| {
        Ok(Some(Identifier {
            r#type: IdentifierType::Certificate,
            ..dummy_identifier()
        }))
    });

    let service = CertificateService {
        certificate_repository: Arc::new(certificate_repository),
        identifier_repository: Arc::new(identifier_repository),
        session_provider: Arc::new(StaticSessionProvider::new_random()),
    };

    let result = service.get_certificate_authority(id).await;
    assert!(matches!(
        result,
        Err(ServiceError::EntityNotFound(
            EntityNotFoundError::Certificate(_)
        ))
    ));
}
