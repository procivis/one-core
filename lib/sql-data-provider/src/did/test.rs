use crate::{did::DidProvider, entity::did, list_query::from_pagination, test_utilities::*};
use one_core::model::common::ExactColumn;
use one_core::model::did::{KeyRole, RelatedKey};
use one_core::model::key::{Key, KeyRelations};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::repository::mock::key_repository::MockKeyRepository;
use one_core::repository::mock::organisation_repository::MockOrganisationRepository;
use one_core::{
    model::{
        common::SortDirection,
        did::{Did, DidId, DidRelations, DidType, DidValue, GetDidQuery, SortableDidColumn},
    },
    repository::{did_repository::DidRepository, error::DataLayerError},
};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use std::sync::Arc;
use time::macros::datetime;
use uuid::Uuid;

struct TestSetup {
    pub provider: DidProvider,
    pub organisation: Organisation,
    pub db: sea_orm::DatabaseConnection,
    pub key: Key,
}

#[derive(Default)]
struct Repositories {
    pub key_repository: MockKeyRepository,
    pub organisation_repository: MockOrganisationRepository,
}

async fn setup_empty(repositories: Repositories) -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();
    let key_id = insert_key_to_database(&db, &organisation_id).await.unwrap();

    TestSetup {
        provider: DidProvider {
            key_repository: Arc::new(repositories.key_repository),
            organisation_repository: Arc::new(repositories.organisation_repository),
            db: db.clone(),
        },
        organisation: Organisation {
            id: Uuid::parse_str(&organisation_id).unwrap(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
        },
        key: Key {
            id: Uuid::parse_str(&key_id).unwrap(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            public_key: "public".to_string(),
            name: "test_key".to_string(),
            private_key: "private".to_string().bytes().collect(),
            storage_type: "INTERNAL".to_string(),
            key_type: "ED25519".to_string(),
            organisation: None,
        },
        db,
    }
}

struct TestSetupWithDid {
    pub provider: DidProvider,
    pub did_name: String,
    pub did_value: DidValue,
    pub did_id: DidId,
    pub organisation: Organisation,
    pub key: Key,
}

async fn setup_with_did(repositories: Repositories) -> TestSetupWithDid {
    let TestSetup {
        provider,
        organisation,
        db,
        key,
        ..
    } = setup_empty(repositories).await;

    let did_name = "test did name";
    let did_value = "test:did";
    let did_id = Uuid::parse_str(
        &insert_did(&db, did_name, did_value, &organisation.id.to_string())
            .await
            .unwrap(),
    )
    .unwrap();

    insert_key_did(&db, &did_id.to_string(), &key.id.to_string())
        .await
        .unwrap();

    TestSetupWithDid {
        provider,
        organisation,
        did_id,
        did_value: did_value.to_string(),
        did_name: did_name.to_string(),
        key,
    }
}

#[tokio::test]
async fn test_create_did() {
    let TestSetup {
        provider,
        organisation,
        key,
        db,
        ..
    } = setup_empty(Repositories::default()).await;

    let id = Uuid::new_v4();
    let result = provider
        .create_did(Did {
            id,
            name: "Name".to_string(),
            organisation: Some(organisation),
            did: "did:key:123".to_owned(),
            did_type: DidType::Local,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            did_method: "KEY".to_string(),
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key,
            }]),
        })
        .await;

    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(id, response);

    assert_eq!(crate::entity::Did::find().all(&db).await.unwrap().len(), 1);
    assert_eq!(
        crate::entity::key_did::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn test_create_did_invalid_organisation() {
    let TestSetup { provider, .. } = setup_empty(Repositories::default()).await;

    let result = provider
        .create_did(Did {
            id: Uuid::new_v4(),
            name: "Name".to_string(),
            organisation: None,
            did: "did:key:123".to_owned(),
            did_type: DidType::Local,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            did_method: "KEY".to_string(),
            keys: None,
        })
        .await;
    assert!(matches!(result, Err(DataLayerError::MappingError)));
}

#[tokio::test]
async fn test_get_did_by_value_existing() {
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .returning(|id, _| {
            Ok(Organisation {
                id: id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            })
        });

    let TestSetupWithDid {
        provider,
        did_id,
        did_name,
        did_value,
        organisation,
        ..
    } = setup_with_did(Repositories {
        organisation_repository,
        ..Default::default()
    })
    .await;

    let result = provider
        .get_did_by_value(
            &did_value.to_string(),
            &DidRelations {
                organisation: Some(OrganisationRelations::default()),
                ..Default::default()
            },
        )
        .await;

    assert!(result.is_ok());

    let content = result.unwrap();
    assert_eq!(content.id, did_id);
    assert_eq!(content.did_method, "KEY");
    assert_eq!(content.did_type, DidType::Local);
    assert_eq!(content.did, did_value);
    assert_eq!(content.name, did_name);
    assert_eq!(content.organisation.unwrap().id, organisation.id);
}

#[tokio::test]
async fn test_get_did_by_value_missing() {
    let TestSetupWithDid { provider, .. } = setup_with_did(Repositories::default()).await;

    let result = provider
        .get_did_by_value(&"missing".to_string(), &DidRelations::default())
        .await;

    assert!(matches!(result, Err(DataLayerError::RecordNotFound)));
}

#[tokio::test]
async fn test_get_did_existing() {
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .returning(|id, _| {
            Ok(Organisation {
                id: id.to_owned(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            })
        });

    let mut key_repository = MockKeyRepository::default();
    key_repository.expect_get_key().times(1).returning(|id, _| {
        Ok(Key {
            id: id.to_owned(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            public_key: "public".to_string(),
            name: "test_key".to_string(),
            private_key: "private".to_string().bytes().collect(),
            storage_type: "INTERNAL".to_string(),
            key_type: "ED25519".to_string(),
            organisation: None,
        })
    });

    let TestSetupWithDid {
        provider,
        did_id,
        did_name,
        did_value,
        organisation,
        key,
        ..
    } = setup_with_did(Repositories {
        organisation_repository,
        key_repository,
    })
    .await;

    let result = provider
        .get_did(
            &did_id,
            &DidRelations {
                organisation: Some(OrganisationRelations::default()),
                keys: Some(KeyRelations::default()),
            },
        )
        .await;

    assert!(result.is_ok());

    let content = result.unwrap();
    assert_eq!(content.id, did_id);
    assert_eq!(content.did_method, "KEY");
    assert_eq!(content.did_type, DidType::Local);
    assert_eq!(content.did, did_value);
    assert_eq!(content.name, did_name);

    assert_eq!(content.organisation.unwrap().id, organisation.id);
    let keys = content.keys.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key.id, key.id);
}

#[tokio::test]
async fn test_get_did_not_existing() {
    let TestSetup { provider, .. } = setup_empty(Repositories::default()).await;

    let result = provider
        .get_did(&Uuid::new_v4(), &DidRelations::default())
        .await;

    assert!(matches!(result, Err(DataLayerError::RecordNotFound)));
}

#[tokio::test]
async fn test_get_did_list_one_did() {
    let TestSetupWithDid {
        provider,
        did_id,
        organisation,
        ..
    } = setup_with_did(Repositories::default()).await;

    let result = provider
        .get_did_list(from_pagination(0, 1, organisation.id.to_string()))
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(1, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(1, response.values.len());
    assert_eq!(did_id, response.values[0].id);
}

#[tokio::test]
async fn test_get_did_list_empty_result() {
    let TestSetup {
        provider,
        organisation,
        ..
    } = setup_empty(Repositories::default()).await;

    let result = provider
        .get_did_list(from_pagination(0, 1, organisation.id.to_string()))
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(0, response.total_items);
    assert_eq!(0, response.total_pages);
    assert_eq!(0, response.values.len());
}

#[tokio::test]
async fn test_get_did_list_empty_incorrect_organisation() {
    let TestSetupWithDid { provider, .. } = setup_with_did(Repositories::default()).await;

    let result = provider
        .get_did_list(from_pagination(0, 1, Uuid::new_v4().to_string()))
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(0, response.total_items);
    assert_eq!(0, response.total_pages);
    assert_eq!(0, response.values.len());
}

#[tokio::test]
async fn test_get_did_list_pages() {
    let TestSetup {
        provider,
        organisation,
        db,
        ..
    } = setup_empty(Repositories::default()).await;

    for i in 0..50 {
        insert_did(
            &db,
            "test did name",
            &format!("did:key:{}", i),
            &organisation.id.to_string(),
        )
        .await
        .unwrap();
    }

    let result = provider
        .get_did_list(from_pagination(0, 10, organisation.id.to_string()))
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(50, response.total_items);
    assert_eq!(5, response.total_pages);
    assert_eq!(10, response.values.len());

    let result = provider
        .get_did_list(from_pagination(0, 2, organisation.id.to_string()))
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(50, response.total_items);
    assert_eq!(25, response.total_pages);
    assert_eq!(2, response.values.len());

    let result = provider
        .get_did_list(from_pagination(5, 10, organisation.id.to_string()))
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(50, response.total_items);
    assert_eq!(5, response.total_pages);
    assert_eq!(0, response.values.len());
}

#[tokio::test]
async fn test_get_did_list_filtering() {
    let TestSetupWithDid {
        provider,
        did_id,
        did_name,
        did_value,
        organisation,
        ..
    } = setup_with_did(Repositories::default()).await;

    // not found
    let result = provider
        .get_did_list(GetDidQuery {
            page: 0,
            page_size: 2,
            sort: None,
            exact: None,
            sort_direction: None,
            name: Some("not-found".to_owned()),
            organisation_id: organisation.id.to_string(),
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(0, response.values.len());

    // by name starts with
    let result = provider
        .get_did_list(GetDidQuery {
            page: 0,
            page_size: 2,
            sort: None,
            exact: None,
            sort_direction: None,
            name: Some("test".to_owned()),
            organisation_id: organisation.id.to_string(),
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(1, response.values.len());
    assert_eq!(did_id, response.values[0].id);

    // by value
    let result = provider
        .get_did_list(GetDidQuery {
            page: 0,
            page_size: 2,
            sort: None,
            exact: None,
            sort_direction: None,
            name: Some(did_value.to_owned()),
            organisation_id: organisation.id.to_string(),
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(1, response.values.len());

    // exact name
    let result = provider
        .get_did_list(GetDidQuery {
            page: 0,
            page_size: 2,
            sort: None,
            exact: Some(vec![ExactColumn::Name]),
            sort_direction: None,
            name: Some(did_name.to_owned()),
            organisation_id: organisation.id.to_string(),
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(1, response.values.len());
}

#[tokio::test]
async fn test_get_did_list_sorting() {
    let TestSetup {
        provider,
        organisation,
        db,
        ..
    } = setup_empty(Repositories::default()).await;

    let older_a_did = did::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        did: Set("did1:did1".to_owned()),
        created_date: Set(datetime!(2023-02-01 21:00 +0)),
        last_modified: Set(get_dummy_date()),
        name: Set("a".to_owned()),
        type_field: Set(did::DidType::Local),
        method: Set("KEY".to_string()),
        organisation_id: Set(organisation.id.to_string()),
    }
    .insert(&db)
    .await
    .unwrap();

    let newer_b_did = did::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        did: Set("did2:did2".to_owned()),
        created_date: Set(datetime!(2023-02-02 21:00 +0)),
        last_modified: Set(get_dummy_date()),
        name: Set("b".to_owned()),
        type_field: Set(did::DidType::Local),
        method: Set("KEY".to_string()),
        organisation_id: Set(organisation.id.to_string()),
    }
    .insert(&db)
    .await
    .unwrap();

    // sort by name - default Ascending
    let result = provider
        .get_did_list(GetDidQuery {
            page: 0,
            page_size: 2,
            sort: Some(SortableDidColumn::Name),
            exact: None,
            sort_direction: None,
            name: None,
            organisation_id: organisation.id.to_string(),
        })
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(older_a_did.id, response.values[0].id.to_string());

    // sort by name - explicit Descending
    let result = provider
        .get_did_list(GetDidQuery {
            page: 0,
            page_size: 2,
            exact: None,
            sort: Some(SortableDidColumn::Name),
            sort_direction: Some(SortDirection::Descending),
            name: None,
            organisation_id: organisation.id.to_string(),
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(newer_b_did.id, response.values[0].id.to_string());

    // sort by name - explicit Ascending
    let result = provider
        .get_did_list(GetDidQuery {
            page: 0,
            page_size: 2,
            exact: None,
            sort: Some(SortableDidColumn::Name),
            sort_direction: Some(SortDirection::Ascending),
            name: None,
            organisation_id: organisation.id.to_string(),
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(older_a_did.id, response.values[0].id.to_string());

    // sort by CreatedDate - default Ascending
    let result = provider
        .get_did_list(GetDidQuery {
            page: 0,
            page_size: 2,
            exact: None,
            sort: Some(SortableDidColumn::CreatedDate),
            sort_direction: None,
            name: None,
            organisation_id: organisation.id.to_string(),
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(older_a_did.id, response.values[0].id.to_string());

    // sort by CreatedDate - explicit Descending
    let result = provider
        .get_did_list(GetDidQuery {
            page: 0,
            page_size: 2,
            exact: None,
            sort: Some(SortableDidColumn::CreatedDate),
            sort_direction: Some(SortDirection::Descending),
            name: None,
            organisation_id: organisation.id.to_string(),
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(newer_b_did.id, response.values[0].id.to_string());

    // sort by CreatedDate - explicit Ascending
    let result = provider
        .get_did_list(GetDidQuery {
            page: 0,
            page_size: 2,
            exact: None,
            sort: Some(SortableDidColumn::CreatedDate),
            sort_direction: Some(SortDirection::Ascending),
            name: None,
            organisation_id: organisation.id.to_string(),
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(older_a_did.id, response.values[0].id.to_string());

    // no sorting specified - default Descending by CreatedDate
    let result = provider
        .get_did_list(from_pagination(0, 2, organisation.id.to_string()))
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(newer_b_did.id, response.values[0].id.to_string());
}
