use super::OrganisationService;
use crate::{
    model::organisation::{Organisation, OrganisationRelations},
    repository::{
        error::DataLayerError, mock::organisation_repository::MockOrganisationRepository,
    },
    service::error::{BusinessLogicError, EntityNotFoundError, ServiceError},
};
use mockall::{predicate::eq, Sequence};
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

fn setup_service(organisation_repository: MockOrganisationRepository) -> OrganisationService {
    OrganisationService {
        organisation_repository: Arc::new(organisation_repository),
    }
}

#[tokio::test]
async fn test_create_organisation_id_not_set() {
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_create_organisation()
        .times(1)
        .returning(|org| Ok(org.id));

    let service = setup_service(organisation_repository);
    let result = service.create_organisation(None).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_organisation_id_set() {
    let mut sequence = Sequence::new();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .in_sequence(&mut sequence)
        .returning(|_, _| Ok(None));
    organisation_repository
        .expect_create_organisation()
        .times(1)
        .in_sequence(&mut sequence)
        .returning(|org| Ok(org.id));

    let service = setup_service(organisation_repository);
    let id = Uuid::new_v4();
    let result = service.create_organisation(Some(id)).await.unwrap();

    assert_eq!(result, id);
}

#[tokio::test]
async fn test_create_organisation_already_exists() {
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .returning(|id, _| {
            Ok(Some(Organisation {
                id: id.to_owned(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }))
        });

    let service = setup_service(organisation_repository);
    let id = Uuid::new_v4();
    let result = service.create_organisation(Some(id)).await;

    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::OrganisationAlreadyExists
        ))
    ));
}

#[tokio::test]
async fn test_get_organisation_success() {
    let mut organisation_repository = MockOrganisationRepository::default();

    let organisation = Organisation {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
    };
    let org_clone = organisation.clone();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(
            eq(organisation.id.to_owned()),
            eq(OrganisationRelations::default()),
        )
        .returning(move |_, _| Ok(Some(org_clone.clone())));

    let service = setup_service(organisation_repository);
    let result = service.get_organisation(&organisation.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, organisation.id);
    assert_eq!(result.created_date, organisation.created_date);
    assert_eq!(result.last_modified, organisation.last_modified);
}

#[tokio::test]
async fn test_get_organisation_failure() {
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .returning(|_, _| Ok(None));

    let service = setup_service(organisation_repository);
    let result = service.get_organisation(&Uuid::new_v4()).await;

    assert!(matches!(
        result,
        Err(ServiceError::EntityNotFound(
            EntityNotFoundError::Organisation(_)
        ))
    ));
}

#[tokio::test]
async fn test_get_organisation_list_success() {
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation_list()
        .times(1)
        .returning(|| {
            Ok(vec![Organisation {
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }])
        });

    let service = setup_service(organisation_repository);
    let result = service.get_organisation_list().await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.len(), 1);
}

#[tokio::test]
async fn test_get_organisation_list_failure() {
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation_list()
        .times(1)
        .returning(|| Err(DataLayerError::Db(anyhow::anyhow!("TEST"))));

    let service = setup_service(organisation_repository);
    let result = service.get_organisation_list().await;

    assert!(matches!(
        result,
        Err(ServiceError::Repository(DataLayerError::Db(_)))
    ));
}
