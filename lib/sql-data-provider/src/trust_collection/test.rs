use std::sync::Arc;

use one_core::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use one_core::model::list_query::ListPagination;
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::model::trust_collection::{
    TrustCollection, TrustCollectionFilterValue, TrustCollectionListQuery, TrustCollectionRelations,
};
use one_core::repository::organisation_repository::MockOrganisationRepository;
use one_core::repository::trust_collection_repository::TrustCollectionRepository;
use sea_orm::DatabaseConnection;
use shared_types::OrganisationId;
use url::Url;
use uuid::Uuid;

use crate::test_utilities::{
    get_dummy_date, insert_organisation_to_database, setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;
use crate::trust_collection::TrustCollectionProvider;

struct TestSetup {
    pub db: DatabaseConnection,
    pub provider: TrustCollectionProvider,
    pub org_id: OrganisationId,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;
    let org_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();
    TestSetup {
        provider: TrustCollectionProvider {
            db: TransactionManagerImpl::new(db.clone()),
            organisation_repository: Arc::new(MockOrganisationRepository::default()),
        },
        db,
        org_id,
    }
}

fn dummy_trust_collection(org_id: OrganisationId) -> TrustCollection {
    TrustCollection {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test-collection".to_string(),
        organisation_id: org_id,
        organisation: None,
        deactivated_at: None,
        remote_trust_collection_url: Some(Url::parse("https://example.com").unwrap()),
    }
}

#[tokio::test]
async fn test_create_trust_collection() {
    let TestSetup {
        provider, org_id, ..
    } = setup().await;

    let collection = dummy_trust_collection(org_id);
    let id = collection.id;

    let result = provider.create(collection).await;
    assert!(result.is_ok());
    similar_asserts::assert_eq!(result.unwrap(), id);
}

#[tokio::test]
async fn test_get_trust_collection_missing() {
    let TestSetup { provider, .. } = setup().await;

    let result = provider
        .get(&Uuid::new_v4().into(), &TrustCollectionRelations::default())
        .await;
    assert!(matches!(result, Ok(None)));
}

#[tokio::test]
async fn test_get_trust_collection_success() {
    let TestSetup {
        provider, org_id, ..
    } = setup().await;

    let collection = dummy_trust_collection(org_id);
    let id = collection.id;
    provider.create(collection).await.unwrap();

    let result = provider
        .get(&id, &TrustCollectionRelations::default())
        .await;

    assert!(result.is_ok());
    let found = result.unwrap().unwrap();
    similar_asserts::assert_eq!(found.id, id);
    similar_asserts::assert_eq!(found.name, "test-collection");
}

#[tokio::test]
async fn test_delete_trust_collection() {
    let TestSetup {
        provider, org_id, ..
    } = setup().await;

    let collection = dummy_trust_collection(org_id);
    let id = collection.id;
    provider.create(collection).await.unwrap();

    let result = provider.delete(id).await;
    assert!(result.is_ok());

    let get_result = provider
        .get(&id, &TrustCollectionRelations::default())
        .await;
    assert!(matches!(get_result, Ok(None)));
}

#[tokio::test]
async fn test_list_trust_collection() {
    let TestSetup {
        provider, org_id, ..
    } = setup().await;

    let collection1 = dummy_trust_collection(org_id);
    let collection2 = {
        let mut c = dummy_trust_collection(org_id);
        c.name = "second-collection".to_string();
        c
    };
    provider.create(collection1).await.unwrap();
    provider.create(collection2).await.unwrap();

    let result = provider
        .list(TrustCollectionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    similar_asserts::assert_eq!(list.total_items, 2);
    similar_asserts::assert_eq!(list.total_pages, 1);
    similar_asserts::assert_eq!(list.values.len(), 2);
}

#[tokio::test]
async fn test_list_trust_collection_with_name_filter() {
    let TestSetup {
        provider, org_id, ..
    } = setup().await;

    let collection1 = dummy_trust_collection(org_id);
    let collection2 = {
        let mut c = dummy_trust_collection(org_id);
        c.name = "second-collection".to_string();
        c
    };
    provider.create(collection1).await.unwrap();
    provider.create(collection2).await.unwrap();

    let result = provider
        .list(TrustCollectionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(
                TrustCollectionFilterValue::Name(
                    one_core::model::list_filter::StringMatch::equals("second-collection"),
                )
                .condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    similar_asserts::assert_eq!(list.total_items, 1);
    similar_asserts::assert_eq!(list.values[0].name, "second-collection");
}

#[tokio::test]
async fn test_list_trust_collection_with_organisation_filter() {
    let TestSetup {
        db,
        provider,
        org_id,
    } = setup().await;

    let other_org_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    let collection1 = dummy_trust_collection(org_id);
    let collection2 = {
        let mut c = dummy_trust_collection(other_org_id);
        c.name = "second-collection".to_string();
        c
    };
    provider.create(collection1).await.unwrap();
    provider.create(collection2).await.unwrap();

    let result = provider
        .list(TrustCollectionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(TrustCollectionFilterValue::OrganisationId(org_id).condition()),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    similar_asserts::assert_eq!(list.total_items, 1);
    similar_asserts::assert_eq!(list.values[0].organisation_id, org_id);
}

#[tokio::test]
async fn test_list_trust_collection_filter_by_created_date() {
    let TestSetup {
        provider, org_id, ..
    } = setup().await;

    let collection1 = dummy_trust_collection(org_id);
    provider.create(collection1).await.unwrap();

    let result = provider
        .list(TrustCollectionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(
                TrustCollectionFilterValue::CreatedDate(ValueComparison {
                    comparison: ComparisonType::GreaterThan,
                    value: get_dummy_date(),
                })
                .condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    // dummy_date is 2005, created_date is set to dummy_date, so nothing is after it
    similar_asserts::assert_eq!(list.total_items, 0);
}

#[tokio::test]
async fn test_list_trust_collection_pagination() {
    let TestSetup {
        provider, org_id, ..
    } = setup().await;

    for i in 0..5 {
        let mut c = dummy_trust_collection(org_id);
        c.name = format!("collection-{i}");
        provider.create(c).await.unwrap();
    }

    let result = provider
        .list(TrustCollectionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    similar_asserts::assert_eq!(list.total_items, 5);
    similar_asserts::assert_eq!(list.total_pages, 3);
    similar_asserts::assert_eq!(list.values.len(), 2);
}
#[tokio::test]
async fn test_get_trust_collection_with_organisation_relation() {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let org_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    let mut mock_org_repo = MockOrganisationRepository::default();
    mock_org_repo
        .expect_get_organisation()
        .returning(move |id, _relations| {
            Ok(Some(Organisation {
                id: *id,
                name: "test-org".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                deactivated_at: None,
                wallet_provider: None,
                wallet_provider_issuer: None,
            }))
        });

    let provider = TrustCollectionProvider {
        db: TransactionManagerImpl::new(db.clone()),
        organisation_repository: Arc::new(mock_org_repo),
    };

    let collection = dummy_trust_collection(org_id);
    let id = collection.id;
    provider.create(collection).await.unwrap();

    let result = provider
        .get(
            &id,
            &TrustCollectionRelations {
                organisation: Some(OrganisationRelations::default()),
            },
        )
        .await;

    assert!(result.is_ok());
    let found = result.unwrap().unwrap();
    assert!(found.organisation.is_some());
    similar_asserts::assert_eq!(found.organisation.unwrap().name, "test-org");
}
