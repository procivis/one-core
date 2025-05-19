use std::str::FromStr;
use std::sync::Arc;

use one_core::model::common::SortDirection;
use one_core::model::did::Did;
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::identifier::{
    Identifier, IdentifierFilterValue, IdentifierListQuery, IdentifierState, IdentifierType,
    SortableIdentifierColumn,
};
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::model::organisation::Organisation;
use one_core::repository::certificate_repository::MockCertificateRepository;
use one_core::repository::did_repository::MockDidRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::history_repository::MockHistoryRepository;
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::key_repository::MockKeyRepository;
use one_core::repository::organisation_repository::MockOrganisationRepository;
use sea_orm::DatabaseConnection;
use shared_types::DidValue;
use uuid::Uuid;

use super::IdentifierProvider;
use super::history::IdentifierHistoryDecorator;
use crate::test_utilities::{
    dummy_organisation, get_dummy_date, insert_did_key, insert_organisation_to_database,
    setup_test_data_layer_and_connection,
};

struct TestSetup {
    pub provider: IdentifierHistoryDecorator,
    pub organisation: Organisation,
    pub did: Did,
    pub db: DatabaseConnection,
}

#[derive(Default)]
struct Repositories {
    pub history_repository: MockHistoryRepository,
    pub organisation_repository: MockOrganisationRepository,
}

async fn setup(repositories: Repositories) -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();
    let organisation = dummy_organisation(Some(organisation_id));

    let did_id = insert_did_key(
        &db,
        "test_did",
        Uuid::new_v4(),
        DidValue::from_str("did:test:123").unwrap(),
        "KEY",
        organisation_id,
    )
    .await
    .unwrap();

    let did = Did {
        id: did_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_did".to_string(),
        did: DidValue::from_str("did:test:123").unwrap(),
        did_type: one_core::model::did::DidType::Local,
        did_method: "KEY".to_string(),
        deactivated: false,
        log: None,
        keys: None,
        organisation: Some(organisation.clone()),
    };

    TestSetup {
        provider: IdentifierHistoryDecorator {
            history_repository: Arc::new(repositories.history_repository),
            inner: Arc::new(IdentifierProvider {
                db: db.clone(),
                organisation_repository: Arc::new(repositories.organisation_repository),
                did_repository: Arc::new(MockDidRepository::default()),
                key_repository: Arc::new(MockKeyRepository::default()),
                certificate_repository: Arc::new(MockCertificateRepository::default()),
            }),
        },
        organisation,
        did,
        db,
    }
}

#[tokio::test]
async fn test_create_and_delete_identifier() {
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .withf(|request| {
            request.entity_type == HistoryEntityType::Identifier
                && request.action == HistoryAction::Created
        })
        .returning(|_| Ok(Uuid::new_v4().into()));
    history_repository
        .expect_create_history()
        .once()
        .withf(|request| {
            request.entity_type == HistoryEntityType::Identifier
                && request.action == HistoryAction::Deleted
        })
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .returning(|_, _| {
            Ok(Some(Organisation {
                id: Uuid::new_v4().into(),
                name: "test_organisation".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            }))
        });

    let setup = setup(Repositories {
        history_repository,
        organisation_repository,
    })
    .await;
    let id = Uuid::new_v4().into();

    let identifier = Identifier {
        id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_identifier".to_string(),
        r#type: IdentifierType::Did,
        is_remote: false,
        state: IdentifierState::Active,
        organisation: Some(setup.organisation),
        did: Some(setup.did),
        key: None,
        certificates: None,
        deleted_at: None,
    };

    assert_eq!(id, setup.provider.create(identifier.clone()).await.unwrap());

    setup.provider.delete(&id).await.unwrap();

    assert!(matches!(
        setup.provider.create(identifier).await,
        Err(DataLayerError::AlreadyExists)
    ));
}

#[tokio::test]
async fn test_get_identifier() {
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .withf(|request| {
            request.entity_type == HistoryEntityType::Identifier
                && request.action == HistoryAction::Created
        })
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .returning(|_, _| {
            Ok(Some(Organisation {
                id: Uuid::new_v4().into(),
                name: "test_organisation".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            }))
        });

    let setup = setup(Repositories {
        history_repository,
        organisation_repository,
    })
    .await;
    let id = Uuid::new_v4().into();

    let identifier = Identifier {
        id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_identifier".to_string(),
        r#type: IdentifierType::Did,
        is_remote: false,
        state: IdentifierState::Active,
        organisation: Some(setup.organisation.clone()),
        did: Some(setup.did.clone()),
        key: None,
        certificates: None,
        deleted_at: None,
    };

    setup.provider.create(identifier.clone()).await.unwrap();

    let non_existent_id = Uuid::new_v4().into();
    assert!(
        setup
            .provider
            .get(non_existent_id, &Default::default())
            .await
            .unwrap()
            .is_none()
    );

    let retrieved = setup
        .provider
        .get(id, &Default::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved.id, identifier.id);
    assert_eq!(retrieved.name, identifier.name);
    assert_eq!(retrieved.r#type, identifier.r#type);
    assert_eq!(retrieved.state, identifier.state);
    assert_eq!(retrieved.is_remote, identifier.is_remote);
    assert_eq!(
        retrieved.organisation.unwrap().id,
        identifier.organisation.unwrap().id
    );
    assert!(retrieved.did.is_none());
    assert!(retrieved.key.is_none());
}

#[tokio::test]
async fn test_get_identifier_list() {
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .times(2)
        .withf(|request| {
            request.entity_type == HistoryEntityType::Identifier
                && request.action == HistoryAction::Created
        })
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .returning(|_, _| {
            Ok(Some(Organisation {
                id: Uuid::new_v4().into(),
                name: "test_organisation".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            }))
        });

    let setup = setup(Repositories {
        history_repository,
        organisation_repository,
    })
    .await;
    let id1 = Uuid::new_v4().into();
    let id2 = Uuid::new_v4().into();

    let identifier1 = Identifier {
        id: id1,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_identifier1".to_string(),
        r#type: IdentifierType::Did,
        is_remote: false,
        state: IdentifierState::Active,
        organisation: Some(setup.organisation.clone()),
        did: Some(setup.did.clone()),
        key: None,
        certificates: None,
        deleted_at: None,
    };

    let did2_id = insert_did_key(
        &setup.db,
        "test_did2",
        Uuid::new_v4(),
        DidValue::from_str("did:test:124").unwrap(),
        "KEY",
        setup.organisation.id,
    )
    .await
    .unwrap();

    let did2 = Did {
        id: did2_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_did2".to_string(),
        did: DidValue::from_str("did:test:124").unwrap(),
        did_type: one_core::model::did::DidType::Local,
        did_method: "KEY".to_string(),
        deactivated: false,
        log: None,
        keys: None,
        organisation: Some(setup.organisation.clone()),
    };

    let identifier2 = Identifier {
        id: id2,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_identifier2".to_string(),
        r#type: IdentifierType::Did,
        is_remote: true,
        state: IdentifierState::Active,
        organisation: Some(setup.organisation.clone()),
        did: Some(did2),
        key: None,
        certificates: None,
        deleted_at: None,
    };

    setup.provider.create(identifier1.clone()).await.unwrap();
    setup.provider.create(identifier2.clone()).await.unwrap();

    let query = IdentifierListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: Some(ListSorting {
            column: SortableIdentifierColumn::CreatedDate,
            direction: Some(SortDirection::Descending),
        }),
        filtering: Some(ListFilterCondition::Value(
            IdentifierFilterValue::OrganisationId(setup.organisation.id),
        )),
        include: None,
    };

    let result = setup.provider.get_identifier_list(query).await.unwrap();
    assert_eq!(result.total_items, 2);
    assert_eq!(result.total_pages, 1);
    assert_eq!(result.values.len(), 2);

    let query = IdentifierListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 1,
        }),
        sorting: Some(ListSorting {
            column: SortableIdentifierColumn::Name,
            direction: Some(SortDirection::Ascending),
        }),
        filtering: Some(ListFilterCondition::Value(IdentifierFilterValue::Types(
            vec![IdentifierType::Did],
        ))),
        include: None,
    };

    let result = setup.provider.get_identifier_list(query).await.unwrap();
    assert_eq!(result.total_items, 2);
    assert_eq!(result.total_pages, 2);
    assert_eq!(result.values.len(), 1);
    assert_eq!(result.values[0].id, id1);
}
