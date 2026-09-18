use std::sync::Arc;

use one_core::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use one_core::model::list_query::ListPagination;
use one_core::model::organisation::UpdateOrganisationRequest;
use one_core::model::trust_collection::{
    TrustCollection, TrustCollectionFilterValue, TrustCollectionListQuery,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::repository::trust_collection_repository::TrustCollectionRepository;
use one_core::service::test_utilities::dummy_organisation;
use sea_orm::DatabaseConnection;
use shared_types::OrganisationId;
use similar_asserts::assert_eq;
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
    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub org_id: OrganisationId,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;
    let org_id = insert_organisation_to_database(&db, None).await.unwrap();
    TestSetup {
        provider: TrustCollectionProvider {
            db: TransactionManagerImpl::new(db.clone()),
            organisation_repository: data_layer.organisation_repository.clone(),
        },
        db,
        org_id,
        organisation_repository: data_layer.organisation_repository,
    }
}

fn dummy_trust_collection(org_id: OrganisationId) -> TrustCollection {
    TrustCollection {
        ecosystem: "EUDI".into(),
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test-collection".to_string(),
        organisation: dummy_organisation(Some(org_id)).into(),
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
    assert_eq!(result.unwrap(), id);
}

#[tokio::test]
async fn test_get_trust_collection_missing() {
    let TestSetup { provider, .. } = setup().await;

    let result = provider.get(&Uuid::new_v4().into()).await;
    assert!(matches!(result, Err(DataLayerError::EntityNotFound { .. })));
}

#[tokio::test]
async fn test_get_trust_collection_success() {
    let TestSetup {
        provider, org_id, ..
    } = setup().await;

    let collection = dummy_trust_collection(org_id);
    let id = collection.id;
    provider.create(collection).await.unwrap();

    let result = provider.get(&id).await;

    assert!(result.is_ok());
    let found = result.unwrap();
    assert_eq!(found.id, id);
    assert_eq!(found.name, "test-collection");
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

    let get_result = provider.get(&id).await;
    assert!(matches!(
        get_result,
        Err(DataLayerError::EntityNotFound { .. })
    ));
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
    assert_eq!(list.total_items.unwrap(), 2);
    assert_eq!(list.total_pages.unwrap(), 1);
    assert_eq!(list.values.len(), 2);
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
    assert_eq!(list.total_items.unwrap(), 1);
    assert_eq!(list.values[0].name, "second-collection");
}

#[tokio::test]
async fn test_list_trust_collection_with_organisation_filter() {
    let TestSetup {
        db,
        provider,
        org_id,
        ..
    } = setup().await;

    let other_org_id = insert_organisation_to_database(&db, None).await.unwrap();

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
            filtering: Some(
                TrustCollectionFilterValue::OrganisationId {
                    id: org_id,
                    include_inherited_collections: false,
                }
                .condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items.unwrap(), 1);
    assert_eq!(list.values[0].organisation.id(), org_id);
}

#[tokio::test]
async fn test_list_trust_collection_with_parent_organisation_filter() {
    let TestSetup {
        db,
        provider,
        organisation_repository,
        org_id,
    } = setup().await;

    let parent_org = insert_organisation_to_database(&db, None).await.unwrap();
    organisation_repository
        .update_organisation(
            &org_id,
            UpdateOrganisationRequest {
                parent_organisation: Some(Some(parent_org)),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let collection1 = dummy_trust_collection(org_id);
    let collection2 = {
        let mut c = dummy_trust_collection(parent_org);
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
                TrustCollectionFilterValue::OrganisationId {
                    id: org_id,
                    include_inherited_collections: true,
                }
                .condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items.unwrap(), 2);
}

#[tokio::test]
async fn test_list_trust_collection_with_organisation_filter_no_duplicates_with_multiple_children()
{
    let TestSetup {
        db,
        provider,
        organisation_repository,
        org_id,
    } = setup().await;

    // org_id has two children - the join used to fetch inherited collections
    // must not cause org_id's own collection to be duplicated once per child
    let child1 = insert_organisation_to_database(&db, None).await.unwrap();
    organisation_repository
        .update_organisation(
            &child1,
            UpdateOrganisationRequest {
                parent_organisation: Some(Some(org_id)),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let child2 = insert_organisation_to_database(&db, None).await.unwrap();
    organisation_repository
        .update_organisation(
            &child2,
            UpdateOrganisationRequest {
                parent_organisation: Some(Some(org_id)),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let collection = dummy_trust_collection(org_id);
    let collection_id = collection.id;
    provider.create(collection).await.unwrap();

    let result = provider
        .list(TrustCollectionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(
                TrustCollectionFilterValue::OrganisationId {
                    id: org_id,
                    include_inherited_collections: true,
                }
                .condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items.unwrap(), 1);
    assert_eq!(list.values.len(), 1);
    assert_eq!(list.values[0].id, collection_id);
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
    assert_eq!(list.total_items.unwrap(), 0);
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
    assert_eq!(list.total_items.unwrap(), 5);
    assert_eq!(list.total_pages.unwrap(), 3);
    assert_eq!(list.values.len(), 2);
}
