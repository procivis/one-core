use std::sync::Arc;

use one_core::model::list_filter::{ComparisonType, ListFilterValue, StringMatch, ValueComparison};
use one_core::model::list_query::ListPagination;
use one_core::model::trust_collection::{TrustCollection, TrustCollectionRelations};
use one_core::model::trust_list_role::TrustListRoleEnum;
use one_core::model::trust_list_subscription::{
    TrustListSubscription, TrustListSubscriptionFilterValue, TrustListSubscriptionListQuery,
    TrustListSubscriptionRelations, TrustListSubscriptionState,
};
use one_core::repository::trust_collection_repository::MockTrustCollectionRepository;
use one_core::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use sea_orm::DatabaseConnection;
use shared_types::TrustCollectionId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::test_utilities::{
    get_dummy_date, insert_organisation_to_database, insert_trust_collection_to_database,
    setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;
use crate::trust_list_subscription::TrustListSubscriptionProvider;

struct TestSetup {
    pub db: DatabaseConnection,
    pub provider: TrustListSubscriptionProvider,
    pub trust_collection_id: TrustCollectionId,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;
    let org_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();
    let trust_collection_id = insert_trust_collection_to_database(&db, org_id)
        .await
        .unwrap();

    TestSetup {
        provider: TrustListSubscriptionProvider {
            db: TransactionManagerImpl::new(db.clone()),
            trust_collection_repository: Arc::new(MockTrustCollectionRepository::default()),
        },
        db,
        trust_collection_id,
    }
}

fn dummy_trust_list_subscription(trust_collection_id: TrustCollectionId) -> TrustListSubscription {
    TrustListSubscription {
        id: Uuid::new_v4().into(),
        name: "test-subscription".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        deactivated_at: None,
        r#type: "LoTE".into(),
        reference: "https://example.com/trust-list".to_string(),
        role: TrustListRoleEnum::PidProvider,
        state: TrustListSubscriptionState::Active,
        trust_collection_id,
        trust_collection: None,
    }
}

#[tokio::test]
async fn test_create_trust_list_subscription() {
    let TestSetup {
        provider,
        trust_collection_id,
        ..
    } = setup().await;

    let subscription = dummy_trust_list_subscription(trust_collection_id);
    let id = subscription.id;

    let result = provider.create(subscription).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), id);
}

#[tokio::test]
async fn test_get_trust_list_subscription_missing() {
    let TestSetup { provider, .. } = setup().await;

    let result = provider
        .get(
            &Uuid::new_v4().into(),
            &TrustListSubscriptionRelations::default(),
        )
        .await;
    assert!(matches!(result, Ok(None)));
}

#[tokio::test]
async fn test_get_trust_list_subscription_success() {
    let TestSetup {
        provider,
        trust_collection_id,
        ..
    } = setup().await;

    let subscription = dummy_trust_list_subscription(trust_collection_id);
    let id = subscription.id;
    provider.create(subscription).await.unwrap();

    let result = provider
        .get(&id, &TrustListSubscriptionRelations::default())
        .await;

    assert!(result.is_ok());
    let found = result.unwrap().unwrap();
    assert_eq!(found.id, id);
    assert_eq!(found.name, "test-subscription");
    assert_eq!(found.reference, "https://example.com/trust-list");
    assert_eq!(found.role, TrustListRoleEnum::PidProvider);
    assert_eq!(found.state, TrustListSubscriptionState::Active);
}

#[tokio::test]
async fn test_delete_trust_list_subscription() {
    let TestSetup {
        provider,
        trust_collection_id,
        ..
    } = setup().await;

    let subscription = dummy_trust_list_subscription(trust_collection_id);
    let id = subscription.id;
    provider.create(subscription).await.unwrap();

    let result = provider.delete(id).await;
    assert!(result.is_ok());

    let get_result = provider
        .get(&id, &TrustListSubscriptionRelations::default())
        .await;
    assert!(matches!(get_result, Ok(None)));
}

#[tokio::test]
async fn test_list_trust_list_subscription() {
    let TestSetup {
        provider,
        trust_collection_id,
        ..
    } = setup().await;

    let subscription1 = dummy_trust_list_subscription(trust_collection_id);
    let subscription2 = {
        let mut s = dummy_trust_list_subscription(trust_collection_id);
        s.name = "second-subscription".to_string();
        s.reference = "https://other.com/trust-list".to_string();
        s
    };
    provider.create(subscription1).await.unwrap();
    provider.create(subscription2).await.unwrap();

    let result = provider
        .list(TrustListSubscriptionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 2);
    assert_eq!(list.total_pages, 1);
    assert_eq!(list.values.len(), 2);
}

#[tokio::test]
async fn test_list_trust_list_subscription_with_name_filter() {
    let TestSetup {
        provider,
        trust_collection_id,
        ..
    } = setup().await;

    let subscription1 = dummy_trust_list_subscription(trust_collection_id);
    let subscription2 = {
        let mut s = dummy_trust_list_subscription(trust_collection_id);
        s.name = "second-subscription".to_string();
        s.reference = "https://other.com/trust-list".to_string();
        s
    };
    provider.create(subscription1).await.unwrap();
    provider.create(subscription2).await.unwrap();

    let result = provider
        .list(TrustListSubscriptionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(
                TrustListSubscriptionFilterValue::Name(StringMatch::equals("second-subscription"))
                    .condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 1);
    assert_eq!(list.values[0].name, "second-subscription");
}

#[tokio::test]
async fn test_list_trust_list_subscription_with_trust_collection_filter() {
    let TestSetup {
        db,
        provider,
        trust_collection_id,
    } = setup().await;

    let org_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();
    let other_trust_collection_id = insert_trust_collection_to_database(&db, org_id)
        .await
        .unwrap();

    let subscription1 = dummy_trust_list_subscription(trust_collection_id);
    let subscription2 = {
        let mut s = dummy_trust_list_subscription(other_trust_collection_id);
        s.name = "second-subscription".to_string();
        s.reference = "https://other.com/trust-list".to_string();
        s
    };
    provider.create(subscription1).await.unwrap();
    provider.create(subscription2).await.unwrap();

    let result = provider
        .list(TrustListSubscriptionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(
                TrustListSubscriptionFilterValue::TrustCollectionId(trust_collection_id)
                    .condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 1);
    assert_eq!(list.values[0].trust_collection_id, trust_collection_id);
}

#[tokio::test]
async fn test_list_trust_list_subscription_with_role_filter() {
    let TestSetup {
        provider,
        trust_collection_id,
        ..
    } = setup().await;

    let subscription1 = dummy_trust_list_subscription(trust_collection_id);
    let subscription2 = {
        let mut s = dummy_trust_list_subscription(trust_collection_id);
        s.name = "second-subscription".to_string();
        s.reference = "https://other.com/trust-list".to_string();
        s.role = TrustListRoleEnum::WalletProvider;
        s
    };
    provider.create(subscription1).await.unwrap();
    provider.create(subscription2).await.unwrap();

    let result = provider
        .list(TrustListSubscriptionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(
                TrustListSubscriptionFilterValue::Role(vec![TrustListRoleEnum::PidProvider])
                    .condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 1);
    assert_eq!(list.values[0].role, TrustListRoleEnum::PidProvider);
}

#[tokio::test]
async fn test_list_trust_list_subscription_with_type_filter() {
    let TestSetup {
        provider,
        trust_collection_id,
        ..
    } = setup().await;

    let subscription1 = dummy_trust_list_subscription(trust_collection_id);
    let subscription2 = {
        let mut s = dummy_trust_list_subscription(trust_collection_id);
        s.name = "second-subscription".to_string();
        s.reference = "https://other.com/trust-list".to_string();
        s.r#type = "LoTE2".into();
        s
    };
    provider.create(subscription1).await.unwrap();
    provider.create(subscription2).await.unwrap();

    let result = provider
        .list(TrustListSubscriptionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(
                TrustListSubscriptionFilterValue::Type(vec!["LoTE2".into()]).condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 1);
    assert_eq!(list.values[0].r#type, "LoTE2".into());
}

#[tokio::test]
async fn test_list_trust_list_subscription_with_reference_filter() {
    let TestSetup {
        provider,
        trust_collection_id,
        ..
    } = setup().await;

    let subscription1 = dummy_trust_list_subscription(trust_collection_id);
    let subscription2 = {
        let mut s = dummy_trust_list_subscription(trust_collection_id);
        s.name = "second-subscription".to_string();
        s.reference = "https://other.com/trust-list".to_string();
        s
    };
    provider.create(subscription1).await.unwrap();
    provider.create(subscription2).await.unwrap();

    let result = provider
        .list(TrustListSubscriptionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(
                TrustListSubscriptionFilterValue::Reference(StringMatch::equals(
                    "https://example.com/trust-list",
                ))
                .condition(),
            ),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 1);
    assert_eq!(list.values[0].reference, "https://example.com/trust-list");
}

#[tokio::test]
async fn test_list_trust_list_subscription_filter_by_created_date() {
    let TestSetup {
        provider,
        trust_collection_id,
        ..
    } = setup().await;

    let subscription1 = dummy_trust_list_subscription(trust_collection_id);
    provider.create(subscription1).await.unwrap();

    let result = provider
        .list(TrustListSubscriptionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(
                TrustListSubscriptionFilterValue::CreatedDate(ValueComparison {
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
    assert_eq!(list.total_items, 0);
}

#[tokio::test]
async fn test_list_trust_list_subscription_filter_by_ids() {
    let TestSetup {
        provider,
        trust_collection_id,
        ..
    } = setup().await;

    let subscription1 = dummy_trust_list_subscription(trust_collection_id);
    let subscription2 = {
        let mut s = dummy_trust_list_subscription(trust_collection_id);
        s.name = "second-subscription".to_string();
        s.reference = "https://other.com/trust-list".to_string();
        s
    };
    let id1 = subscription1.id;
    provider.create(subscription1).await.unwrap();
    provider.create(subscription2).await.unwrap();

    let result = provider
        .list(TrustListSubscriptionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            filtering: Some(TrustListSubscriptionFilterValue::Ids(vec![id1]).condition()),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 1);
    assert_eq!(list.values[0].id, id1);
}

#[tokio::test]
async fn test_list_trust_list_subscription_pagination() {
    let TestSetup {
        provider,
        trust_collection_id,
        ..
    } = setup().await;

    for i in 0..5 {
        let mut s = dummy_trust_list_subscription(trust_collection_id);
        s.name = format!("subscription-{i}");
        s.reference = format!("https://other.com/trust-list/{i}");
        provider.create(s).await.unwrap();
    }

    let result = provider
        .list(TrustListSubscriptionListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 2,
            }),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let list = result.unwrap();
    assert_eq!(list.total_items, 5);
    assert_eq!(list.total_pages, 3);
    assert_eq!(list.values.len(), 2);
}

#[tokio::test]
async fn test_get_trust_list_subscription_with_trust_collection_relation() {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let org_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();
    let trust_collection_id = insert_trust_collection_to_database(&db, org_id)
        .await
        .unwrap();

    let mut mock_collection_repo = MockTrustCollectionRepository::default();
    mock_collection_repo
        .expect_get()
        .returning(move |id, _relations| {
            Ok(Some(TrustCollection {
                id: *id,
                name: "test-collection".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                organisation_id: org_id,
                organisation: None,
                deactivated_at: None,
            }))
        });

    let provider = TrustListSubscriptionProvider {
        db: TransactionManagerImpl::new(db.clone()),
        trust_collection_repository: Arc::new(mock_collection_repo),
    };

    let subscription = dummy_trust_list_subscription(trust_collection_id);
    let id = subscription.id;
    provider.create(subscription).await.unwrap();

    let result = provider
        .get(
            &id,
            &TrustListSubscriptionRelations {
                trust_collection: Some(TrustCollectionRelations::default()),
            },
        )
        .await;

    assert!(result.is_ok());
    let found = result.unwrap().unwrap();
    assert!(found.trust_collection.is_some());
    assert_eq!(found.trust_collection.unwrap().name, "test-collection");
}
