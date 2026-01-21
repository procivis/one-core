use std::sync::Arc;

use uuid::Uuid;

use crate::model::identifier::{Identifier, IdentifierListQuery};
use crate::proto::identifier_creator::MockIdentifierCreator;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::service::error::{ServiceError, ValidationError};
use crate::service::identifier::IdentifierService;
use crate::service::identifier::dto::CreateIdentifierRequestDTO;
use crate::service::test_utilities::{dummy_identifier, dummy_organisation, generic_config};

#[tokio::test]
async fn test_get_identifier_list_session_org_mismatch() {
    let service = setup_service(None);

    let result = service
        .get_identifier_list(
            &Uuid::new_v4().into(),
            IdentifierListQuery {
                pagination: None,
                sorting: None,
                filtering: None,
                include: None,
            },
        )
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}

#[tokio::test]
async fn test_create_identifier_session_org_mismatch() {
    let service = setup_service(None);

    let result = service
        .create_identifier(CreateIdentifierRequestDTO {
            name: "".to_string(),
            did: None,
            key: None,
            key_id: None,
            certificates: None,
            certificate_authorities: None,
            organisation_id: Uuid::new_v4().into(),
        })
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}

#[tokio::test]
async fn test_identifier_ops_session_org_mismatch() {
    let mut identifier = dummy_identifier();
    identifier.organisation = Some(dummy_organisation(None));
    let service = setup_service(Some(identifier));

    let result = service.get_identifier(&Uuid::new_v4().into()).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));

    let result = service.delete_identifier(&Uuid::new_v4().into()).await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(ValidationError::Forbidden))
    ));
}

fn setup_service(identifier: Option<Identifier>) -> IdentifierService {
    let key_repository = Arc::new(MockKeyRepository::default());
    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .returning(move |_, _| Ok(identifier.clone()));
    let identifier_repository = Arc::new(identifier_repository);
    let organisation_repository = Arc::new(MockOrganisationRepository::default());
    let config = Arc::new(generic_config().core);
    let session_provider = Arc::new(StaticSessionProvider::new_random());

    IdentifierService {
        identifier_repository,
        key_repository,
        organisation_repository,
        config,
        identifier_creator: Arc::new(MockIdentifierCreator::default()),
        session_provider,
    }
}
