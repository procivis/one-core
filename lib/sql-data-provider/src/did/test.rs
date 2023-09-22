use crate::{did::DidProvider, entity::did, list_query::from_pagination, test_utilities::*};
use one_core::model::common::ExactColumn;
use one_core::{
    model::{
        common::SortDirection,
        did::{Did, DidId, DidRelations, DidType, DidValue, GetDidQuery, SortableDidColumn},
        organisation::OrganisationId,
    },
    repository::{did_repository::DidRepository, error::DataLayerError},
};
use sea_orm::{ActiveModelTrait, Set};
use time::macros::datetime;
use uuid::Uuid;

struct TestSetup {
    pub provider: DidProvider,
    pub organisation_id: OrganisationId,
    pub db: sea_orm::DatabaseConnection,
}

async fn setup_empty() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();

    TestSetup {
        provider: DidProvider { db: db.clone() },
        organisation_id: Uuid::parse_str(&organisation_id).unwrap(),
        db,
    }
}

struct TestSetupWithDid {
    pub provider: DidProvider,
    pub did_name: String,
    pub did_value: DidValue,
    pub did_id: DidId,
    pub organisation_id: OrganisationId,
}

async fn setup_with_did() -> TestSetupWithDid {
    let TestSetup {
        provider,
        organisation_id,
        db,
    } = setup_empty().await;

    let did_name = "test did name";
    let did_value = "test:did";
    let did_id = Uuid::parse_str(
        &insert_did(&db, did_name, did_value, &organisation_id.to_string())
            .await
            .unwrap(),
    )
    .unwrap();

    TestSetupWithDid {
        provider,
        organisation_id,
        did_id,
        did_value: did_value.to_string(),
        did_name: did_name.to_string(),
    }
}

#[tokio::test]
async fn test_create_did() {
    let TestSetup {
        provider,
        organisation_id,
        ..
    } = setup_empty().await;

    let id = Uuid::new_v4();
    let result = provider
        .create_did(Did {
            id,
            name: "Name".to_string(),
            organisation_id,
            did: "did:key:123".to_owned(),
            did_type: DidType::Local,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            did_method: "KEY".to_string(),
        })
        .await;

    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(id, response);
}

#[tokio::test]
async fn test_create_did_invalid_organisation() {
    let TestSetup { provider, .. } = setup_empty().await;

    let missing_organisation = Uuid::new_v4();
    let result = provider
        .create_did(Did {
            id: Uuid::new_v4(),
            name: "Name".to_string(),
            organisation_id: missing_organisation,
            did: "did:key:123".to_owned(),
            did_type: DidType::Local,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            did_method: "KEY".to_string(),
        })
        .await;
    assert!(matches!(result, Err(DataLayerError::IncorrectParameters)));
}

#[tokio::test]
async fn test_get_did_by_value_existing() {
    let TestSetupWithDid {
        provider,
        did_id,
        did_name,
        did_value,
        organisation_id,
        ..
    } = setup_with_did().await;

    let result = provider
        .get_did_by_value(&did_value.to_string(), &DidRelations::default())
        .await;

    assert!(result.is_ok());

    let content = result.unwrap();
    assert_eq!(content.id, did_id);
    assert_eq!(content.did_method, "KEY");
    assert_eq!(content.did_type, DidType::Local);
    assert_eq!(content.did, did_value);
    assert_eq!(content.name, did_name);
    assert_eq!(content.organisation_id, organisation_id);
}

#[tokio::test]
async fn test_get_did_by_value_missing() {
    let TestSetupWithDid { provider, .. } = setup_with_did().await;

    let result = provider
        .get_did_by_value(&"missing".to_string(), &DidRelations::default())
        .await;

    assert!(matches!(result, Err(DataLayerError::RecordNotFound)));
}

#[tokio::test]
async fn test_get_did_existing() {
    let TestSetupWithDid {
        provider,
        did_id,
        did_name,
        did_value,
        organisation_id,
        ..
    } = setup_with_did().await;

    let result = provider.get_did(&did_id, &DidRelations::default()).await;

    assert!(result.is_ok());

    let content = result.unwrap();
    assert_eq!(content.id, did_id);
    assert_eq!(content.did_method, "KEY");
    assert_eq!(content.did_type, DidType::Local);
    assert_eq!(content.did, did_value);
    assert_eq!(content.name, did_name);
    assert_eq!(content.organisation_id, organisation_id);
}

#[tokio::test]
async fn test_get_did_not_existing() {
    let TestSetup { provider, .. } = setup_empty().await;

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
        organisation_id,
        ..
    } = setup_with_did().await;

    let result = provider
        .get_did_list(from_pagination(0, 1, organisation_id.to_string()))
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
        organisation_id,
        ..
    } = setup_empty().await;

    let result = provider
        .get_did_list(from_pagination(0, 1, organisation_id.to_string()))
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(0, response.total_items);
    assert_eq!(0, response.total_pages);
    assert_eq!(0, response.values.len());
}

#[tokio::test]
async fn test_get_did_list_empty_incorrect_organisation() {
    let TestSetupWithDid { provider, .. } = setup_with_did().await;

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
        organisation_id,
        db,
    } = setup_empty().await;

    for i in 0..50 {
        insert_did(
            &db,
            "test did name",
            &format!("did:key:{}", i),
            &organisation_id.to_string(),
        )
        .await
        .unwrap();
    }

    let result = provider
        .get_did_list(from_pagination(0, 10, organisation_id.to_string()))
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(50, response.total_items);
    assert_eq!(5, response.total_pages);
    assert_eq!(10, response.values.len());

    let result = provider
        .get_did_list(from_pagination(0, 2, organisation_id.to_string()))
        .await;

    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(50, response.total_items);
    assert_eq!(25, response.total_pages);
    assert_eq!(2, response.values.len());

    let result = provider
        .get_did_list(from_pagination(5, 10, organisation_id.to_string()))
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
        organisation_id,
        ..
    } = setup_with_did().await;

    // not found
    let result = provider
        .get_did_list(GetDidQuery {
            page: 0,
            page_size: 2,
            sort: None,
            exact: None,
            sort_direction: None,
            name: Some("not-found".to_owned()),
            organisation_id: organisation_id.to_string(),
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
            organisation_id: organisation_id.to_string(),
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
            organisation_id: organisation_id.to_string(),
        })
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(0, response.values.len());

    // exact
    let result = provider
        .get_did_list(GetDidQuery {
            page: 0,
            page_size: 2,
            sort: None,
            exact: Some(vec![ExactColumn::Name]),
            sort_direction: None,
            name: Some(did_name.to_owned()),
            organisation_id: organisation_id.to_string(),
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
        organisation_id,
        db,
    } = setup_empty().await;

    let older_a_did = did::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        did: Set("did1:did1".to_owned()),
        created_date: Set(datetime!(2023-02-01 21:00 +0)),
        last_modified: Set(get_dummy_date()),
        name: Set("a".to_owned()),
        type_field: Set(did::DidType::Local),
        method: Set("KEY".to_string()),
        organisation_id: Set(organisation_id.to_string()),
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
        organisation_id: Set(organisation_id.to_string()),
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
            organisation_id: organisation_id.to_string(),
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
            organisation_id: organisation_id.to_string(),
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
            organisation_id: organisation_id.to_string(),
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
            organisation_id: organisation_id.to_string(),
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
            organisation_id: organisation_id.to_string(),
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
            organisation_id: organisation_id.to_string(),
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
        .get_did_list(from_pagination(0, 2, organisation_id.to_string()))
        .await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(2, response.total_items);
    assert_eq!(1, response.total_pages);
    assert_eq!(2, response.values.len());
    assert_eq!(newer_b_did.id, response.values[0].id.to_string());
}
