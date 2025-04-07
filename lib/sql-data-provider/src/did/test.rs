use std::sync::Arc;

use one_core::model::common::SortDirection;
use one_core::model::did::{
    Did, DidFilterValue, DidListQuery, DidRelations, DidType, KeyRole, RelatedKey,
    SortableDidColumn,
};
use one_core::model::key::{Key, KeyRelations};
use one_core::model::list_filter::{ListFilterCondition, StringMatch, StringMatchType};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::repository::did_repository::DidRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::key_repository::MockKeyRepository;
use one_core::repository::organisation_repository::MockOrganisationRepository;
use sea_orm::ActiveValue::NotSet;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use shared_types::{DidId, DidValue};
use time::macros::datetime;
use uuid::Uuid;

use super::DidProvider;
use crate::entity::did;
use crate::test_utilities::*;

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

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();
    let key_id = insert_key_to_database(
        &db,
        "ED25519".to_string(),
        vec![],
        vec![],
        None,
        organisation_id,
    )
    .await
    .unwrap();

    TestSetup {
        provider: DidProvider {
            key_repository: Arc::new(repositories.key_repository),
            organisation_repository: Arc::new(repositories.organisation_repository),
            db: db.clone(),
        },
        organisation: dummy_organisation(Some(organisation_id)),
        key: Key {
            id: key_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            public_key: vec![],
            name: "test_key".to_string(),
            key_reference: "private".to_string().bytes().collect(),
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
    let did_value: DidValue = "did:test:123".parse().unwrap();
    let did_id = &insert_did_key(
        &db,
        did_name,
        Uuid::new_v4(),
        did_value.clone(),
        "KEY",
        organisation.id,
    )
    .await
    .unwrap();

    insert_key_did(&db, *did_id, key.id, KeyRole::Authentication.into())
        .await
        .unwrap();

    TestSetupWithDid {
        provider,
        organisation,
        did_id: *did_id,
        did_value,
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

    let id = Uuid::new_v4().into();
    let result = provider
        .create_did(Did {
            id,
            name: "Name".to_string(),
            organisation: Some(organisation),
            did: "did:key:123".parse().unwrap(),
            did_type: DidType::Local,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            did_method: "KEY".to_string(),
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key,
            }]),
            deactivated: false,
            log: None,
        })
        .await;

    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(id, response);

    assert_eq!(
        crate::entity::did::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );
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

    let non_existing_organisation = dummy_organisation(None);

    let result = provider
        .create_did(Did {
            id: Uuid::new_v4().into(),
            name: "Name".to_string(),
            organisation: Some(non_existing_organisation),
            did: "did:key:123".parse().unwrap(),
            did_type: DidType::Local,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            did_method: "KEY".to_string(),
            keys: None,
            deactivated: false,
            log: None,
        })
        .await;
    assert!(matches!(result, Err(DataLayerError::IncorrectParameters)));
}

#[tokio::test]
async fn test_get_did_by_value_existing() {
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .returning(|id, _| Ok(Some(dummy_organisation(Some(*id)))));

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
            &did_value,
            &DidRelations {
                organisation: Some(OrganisationRelations::default()),
                ..Default::default()
            },
        )
        .await;

    assert!(result.is_ok());

    let content = result.unwrap().unwrap();
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
        .get_did_by_value(
            &"did:missing:123".parse().unwrap(),
            &DidRelations::default(),
        )
        .await;

    assert!(matches!(result, Ok(None)));
}

#[tokio::test]
async fn test_get_did_existing() {
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .returning(|id, _| Ok(Some(dummy_organisation(Some(*id)))));

    let mut key_repository = MockKeyRepository::default();
    key_repository.expect_get_key().times(1).returning(|id, _| {
        Ok(Some(Key {
            id: id.to_owned(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            public_key: vec![],
            name: "test_key".to_string(),
            key_reference: "private".to_string().bytes().collect(),
            storage_type: "INTERNAL".to_string(),
            key_type: "ED25519".to_string(),
            organisation: None,
        }))
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

    let content = result.unwrap().unwrap();
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
        .get_did(&Uuid::new_v4().into(), &DidRelations::default())
        .await
        .unwrap();

    assert!(result.is_none());
}

#[tokio::test]
async fn test_get_did_list_one_did() {
    let TestSetupWithDid {
        provider, did_id, ..
    } = setup_with_did(Repositories::default()).await;

    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            ..Default::default()
        })
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
    let TestSetup { provider, .. } = setup_empty(Repositories::default()).await;

    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            ..Default::default()
        })
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
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            filtering: Some(ListFilterCondition::Value(DidFilterValue::OrganisationId(
                Uuid::new_v4().into(),
            ))),
            ..Default::default()
        })
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
        insert_did_key(
            &db,
            &format!("test did name {}", i),
            Uuid::new_v4(),
            format!("did:key:{}", i).parse().unwrap(),
            "KEY",
            organisation.id,
        )
        .await
        .unwrap();
    }

    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(50, response.total_items);
    assert_eq!(5, response.total_pages);
    assert_eq!(10, response.values.len());

    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(50, response.total_items);
    assert_eq!(25, response.total_pages);
    assert_eq!(2, response.values.len());

    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 5,
                page_size: 10,
            }),
            ..Default::default()
        })
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
        ..
    } = setup_with_did(Repositories::default()).await;

    // not found
    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            filtering: Some(ListFilterCondition::Value(DidFilterValue::Name(
                StringMatch {
                    value: "not-found".to_owned(),
                    r#match: StringMatchType::StartsWith,
                },
            ))),
            ..Default::default()
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(0, response.values.len());

    // by name starts with
    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            filtering: Some(ListFilterCondition::Value(DidFilterValue::Name(
                StringMatch {
                    value: "test".to_owned(),
                    r#match: StringMatchType::StartsWith,
                },
            ))),
            ..Default::default()
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(1, response.values.len());
    assert_eq!(did_id, response.values[0].id);

    // by value
    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            filtering: Some(ListFilterCondition::Value(DidFilterValue::Did(
                StringMatch {
                    value: did_value.to_string(),
                    r#match: StringMatchType::Equals,
                },
            ))),
            ..Default::default()
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(1, response.values.len());

    // exact name
    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            filtering: Some(ListFilterCondition::Value(DidFilterValue::Name(
                StringMatch {
                    value: did_name.to_owned(),
                    r#match: StringMatchType::Equals,
                },
            ))),
            ..Default::default()
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
        id: Set(Uuid::new_v4().into()),
        did: Set("did:did1:1".parse().unwrap()),
        created_date: Set(datetime!(2023-02-01 21:00 +0)),
        last_modified: Set(get_dummy_date()),
        name: Set("a".to_owned()),
        type_field: Set(did::DidType::Local),
        method: Set("KEY".to_string()),
        organisation_id: Set(Some(organisation.id)),
        deactivated: Set(false),
        deleted_at: NotSet,
        log: NotSet,
    }
    .insert(&db)
    .await
    .unwrap();

    let newer_b_did = did::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        did: Set("did:did2:2".parse().unwrap()),
        created_date: Set(datetime!(2023-02-02 21:00 +0)),
        last_modified: Set(get_dummy_date()),
        name: Set("b".to_owned()),
        type_field: Set(did::DidType::Local),
        method: Set("KEY".to_string()),
        organisation_id: Set(Some(organisation.id)),
        deactivated: Set(false),
        deleted_at: NotSet,
        log: NotSet,
    }
    .insert(&db)
    .await
    .unwrap();

    // sort by name - default Ascending
    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            sorting: Some(ListSorting {
                column: SortableDidColumn::Name,
                direction: None,
            }),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(older_a_did.id, response.values[0].id);

    // sort by name - explicit Descending
    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            sorting: Some(ListSorting {
                column: SortableDidColumn::Name,
                direction: Some(SortDirection::Descending),
            }),
            ..Default::default()
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(newer_b_did.id, response.values[0].id);

    // sort by name - explicit Ascending
    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            sorting: Some(ListSorting {
                column: SortableDidColumn::Name,
                direction: Some(SortDirection::Ascending),
            }),
            ..Default::default()
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(older_a_did.id, response.values[0].id);

    // sort by CreatedDate - default Ascending
    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            sorting: Some(ListSorting {
                column: SortableDidColumn::CreatedDate,
                direction: None,
            }),
            ..Default::default()
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(older_a_did.id, response.values[0].id);

    // sort by CreatedDate - explicit Descending
    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            sorting: Some(ListSorting {
                column: SortableDidColumn::CreatedDate,
                direction: Some(SortDirection::Descending),
            }),
            ..Default::default()
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(newer_b_did.id, response.values[0].id);

    // sort by CreatedDate - explicit Ascending
    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            sorting: Some(ListSorting {
                column: SortableDidColumn::CreatedDate,
                direction: Some(SortDirection::Ascending),
            }),
            ..Default::default()
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(older_a_did.id, response.values[0].id);

    // no sorting specified - default Descending by CreatedDate
    let result = provider
        .get_did_list(DidListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            ..Default::default()
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(newer_b_did.id, response.values[0].id);
}

#[tokio::test]
async fn test_get_did_list_complex_filter_condition() {
    let TestSetup {
        provider,
        organisation,
        db,
        ..
    } = setup_empty(Repositories::default()).await;

    let older_a_did = did::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        did: Set("did:did1:1".parse().unwrap()),
        created_date: Set(datetime!(2023-02-01 21:00 +0)),
        last_modified: Set(get_dummy_date()),
        name: Set("a".to_owned()),
        type_field: Set(did::DidType::Local),
        method: Set("KEY".to_string()),
        organisation_id: Set(Some(organisation.id)),
        deactivated: Set(false),
        deleted_at: NotSet,
        log: NotSet,
    }
    .insert(&db)
    .await
    .unwrap();

    let newer_b_did = did::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        did: Set("did:did2:2".parse().unwrap()),
        created_date: Set(datetime!(2023-02-02 21:00 +0)),
        last_modified: Set(get_dummy_date()),
        name: Set("b".to_owned()),
        type_field: Set(did::DidType::Local),
        method: Set("KEY".to_string()),
        organisation_id: Set(Some(organisation.id)),
        deactivated: Set(false),
        deleted_at: NotSet,
        log: NotSet,
    }
    .insert(&db)
    .await
    .unwrap();

    // combined filter AND
    let result = provider
        .get_did_list(DidListQuery {
            filtering: Some(ListFilterCondition::<DidFilterValue>::And(vec![
                DidFilterValue::Did(StringMatch {
                    r#match: StringMatchType::Equals,
                    value: older_a_did.did.to_string(),
                })
                .into(),
                DidFilterValue::OrganisationId(organisation.id).into(),
            ])),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(1, response.total_items);
    assert_eq!(1, response.values.len());
    assert_eq!(older_a_did.id, response.values[0].id);

    // combined filter OR
    let result = provider
        .get_did_list(DidListQuery {
            filtering: Some(ListFilterCondition::<DidFilterValue>::Or(vec![
                DidFilterValue::Did(StringMatch {
                    r#match: StringMatchType::Equals,
                    value: older_a_did.did.to_string(),
                })
                .into(),
                DidFilterValue::Name(StringMatch {
                    r#match: StringMatchType::Equals,
                    value: older_a_did.name.to_owned(),
                })
                .into(),
            ])),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(1, response.total_items);
    assert_eq!(1, response.values.len());
    assert_eq!(older_a_did.id, response.values[0].id);

    // combined filter OR/AND
    let condition: ListFilterCondition<DidFilterValue> =
        ListFilterCondition::<DidFilterValue>::from(DidFilterValue::Did(StringMatch {
            r#match: StringMatchType::Equals,
            value: newer_b_did.did.to_string(),
        })) | DidFilterValue::Name(StringMatch {
            r#match: StringMatchType::Equals,
            value: newer_b_did.name.to_owned(),
        }) | None::<DidFilterValue>
            | (ListFilterCondition::<DidFilterValue>::from(Some(DidFilterValue::OrganisationId(
                organisation.id,
            ))) & DidFilterValue::Name(StringMatch {
                r#match: StringMatchType::Equals,
                value: newer_b_did.name.to_owned(),
            }) & None::<DidFilterValue>);
    let result = provider
        .get_did_list(DidListQuery {
            filtering: Some(condition),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(1, response.total_items);
    assert_eq!(1, response.values.len());
    assert_eq!(newer_b_did.id, response.values[0].id);
}
