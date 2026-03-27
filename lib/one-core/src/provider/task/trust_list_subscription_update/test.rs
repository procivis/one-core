use std::sync::Arc;

use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::model::trust_collection::TrustCollection;
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{
    GetTrustListSubscriptionList, TrustListSubscription, TrustListSubscriptionState,
};
use crate::proto::session_provider::NoSessionProvider;
use crate::provider::task::Task;
use crate::provider::task::trust_list_subscription_update::TrustListSubscriptionUpdateTask;
use crate::provider::task::trust_list_subscription_update::dto::UpdateResultDTO;
use crate::provider::trust_list_subscriber::error::TrustListSubscriberError;
use crate::provider::trust_list_subscriber::provider::{
    MockTrustListSubscriberProvider, TrustListSubscriberProvider,
};
use crate::provider::trust_list_subscriber::{MockTrustListSubscriber, TrustListValidationSuccess};
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::trust_list_subscription_repository::MockTrustListSubscriptionRepository;

#[tokio::test]
async fn test_trust_list_subscription_update_active() {
    let validation_result = TrustListValidationSuccess {
        role: TrustListRoleEnum::PidProvider,
    };
    let now = crate::clock::now_utc();
    let collection = TrustCollection {
        id: Uuid::new_v4().into(),
        name: "test collection".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        remote_trust_collection_url: None,
        organisation_id: Uuid::new_v4().into(),
        organisation: None,
    };
    let subscription_id = Uuid::new_v4().into();
    let subscription = TrustListSubscription {
        id: subscription_id,
        name: "subscription 1".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        r#type: "test".into(),
        reference: "https://example.com".to_string(),
        role: TrustListRoleEnum::PidProvider,
        state: TrustListSubscriptionState::Active,
        trust_collection_id: collection.id,
        trust_collection: Some(collection.clone()),
    };
    let subscriptions = vec![subscription.clone()];
    let mut repository = MockTrustListSubscriptionRepository::new();
    repository.expect_list().returning(move |_| {
        Ok(GetTrustListSubscriptionList {
            values: subscriptions.clone(),
            total_pages: 1,
            total_items: subscriptions.clone().len() as u64,
        })
    });
    repository
        .expect_get()
        .returning(move |_, _| Ok(Some(subscription.clone())));

    let task = TrustListSubscriptionUpdateTask::new(
        test_subscriber_provider(Some(validation_result)),
        Arc::new(repository),
        Arc::new(MockHistoryRepository::new()),
        Arc::new(NoSessionProvider),
    );

    let result: UpdateResultDTO = serde_json::from_value(task.run(None).await.unwrap()).unwrap();
    assert_eq!(result.total_checks, 1);
    assert_eq!(result.updated_subscriptions.len(), 0);
}

#[tokio::test]
async fn test_trust_list_subscription_update_error() {
    let now = crate::clock::now_utc();
    let collection = TrustCollection {
        id: Uuid::new_v4().into(),
        name: "test collection".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        remote_trust_collection_url: None,
        organisation_id: Uuid::new_v4().into(),
        organisation: None,
    };
    let subscription_id = Uuid::new_v4().into();
    let subscription = TrustListSubscription {
        id: subscription_id,
        name: "subscription 1".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        r#type: "test".into(),
        reference: "https://example.com".to_string(),
        role: TrustListRoleEnum::PidProvider,
        state: TrustListSubscriptionState::Error,
        trust_collection_id: collection.id,
        trust_collection: Some(collection.clone()),
    };
    let subscriptions = vec![subscription.clone()];
    let mut repository = MockTrustListSubscriptionRepository::new();
    repository.expect_list().returning(move |_| {
        Ok(GetTrustListSubscriptionList {
            values: subscriptions.clone(),
            total_pages: 1,
            total_items: subscriptions.clone().len() as u64,
        })
    });
    repository
        .expect_get()
        .returning(move |_, _| Ok(Some(subscription.clone())));

    let task = TrustListSubscriptionUpdateTask::new(
        test_subscriber_provider(None),
        Arc::new(repository),
        Arc::new(MockHistoryRepository::new()),
        Arc::new(NoSessionProvider),
    );

    let result: UpdateResultDTO = serde_json::from_value(task.run(None).await.unwrap()).unwrap();
    assert_eq!(result.total_checks, 1);
    assert_eq!(result.updated_subscriptions.len(), 0);
}

#[tokio::test]
async fn test_trust_list_subscription_update_active_to_error() {
    let now = crate::clock::now_utc();
    let collection = TrustCollection {
        id: Uuid::new_v4().into(),
        name: "test collection".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        remote_trust_collection_url: None,
        organisation_id: Uuid::new_v4().into(),
        organisation: None,
    };
    let subscription_id = Uuid::new_v4().into();
    let subscription = TrustListSubscription {
        id: subscription_id,
        name: "subscription 1".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        r#type: "test".into(),
        reference: "https://example.com".to_string(),
        role: TrustListRoleEnum::PidProvider,
        state: TrustListSubscriptionState::Active,
        trust_collection_id: collection.id,
        trust_collection: Some(collection.clone()),
    };
    let subscriptions = vec![subscription.clone()];
    let mut repository = MockTrustListSubscriptionRepository::new();
    repository.expect_list().returning(move |_| {
        Ok(GetTrustListSubscriptionList {
            values: subscriptions.clone(),
            total_pages: 1,
            total_items: subscriptions.clone().len() as u64,
        })
    });
    repository
        .expect_get()
        .returning(move |_, _| Ok(Some(subscription.clone())));
    repository
        .expect_update_state()
        .once()
        .returning(move |_, _| Ok(()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));
    let task = TrustListSubscriptionUpdateTask::new(
        test_subscriber_provider(None),
        Arc::new(repository),
        Arc::new(history_repository),
        Arc::new(NoSessionProvider),
    );

    let result: UpdateResultDTO = serde_json::from_value(task.run(None).await.unwrap()).unwrap();
    assert_eq!(result.total_checks, 1);
    assert_eq!(result.updated_subscriptions, vec![subscription_id]);
}

#[tokio::test]
async fn test_trust_list_subscription_update_error_to_active() {
    let validation_result = TrustListValidationSuccess {
        role: TrustListRoleEnum::PidProvider,
    };
    let now = crate::clock::now_utc();
    let collection = TrustCollection {
        id: Uuid::new_v4().into(),
        name: "test collection".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        remote_trust_collection_url: None,
        organisation_id: Uuid::new_v4().into(),
        organisation: None,
    };
    let subscription_id = Uuid::new_v4().into();
    let subscription = TrustListSubscription {
        id: subscription_id,
        name: "subscription 1".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        r#type: "test".into(),
        reference: "https://example.com".to_string(),
        role: TrustListRoleEnum::PidProvider,
        state: TrustListSubscriptionState::Error,
        trust_collection_id: collection.id,
        trust_collection: Some(collection.clone()),
    };
    let subscriptions = vec![subscription.clone()];
    let mut repository = MockTrustListSubscriptionRepository::new();
    repository.expect_list().returning(move |_| {
        Ok(GetTrustListSubscriptionList {
            values: subscriptions.clone(),
            total_pages: 1,
            total_items: subscriptions.clone().len() as u64,
        })
    });
    repository
        .expect_get()
        .returning(move |_, _| Ok(Some(subscription.clone())));
    repository
        .expect_update_state()
        .once()
        .returning(move |_, _| Ok(()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .returning(|_| Ok(Uuid::new_v4().into()));
    let task = TrustListSubscriptionUpdateTask::new(
        test_subscriber_provider(Some(validation_result)),
        Arc::new(repository),
        Arc::new(history_repository),
        Arc::new(NoSessionProvider),
    );

    let result: UpdateResultDTO = serde_json::from_value(task.run(None).await.unwrap()).unwrap();
    assert_eq!(result.total_checks, 1);
    assert_eq!(result.updated_subscriptions, vec![subscription_id]);
}

fn test_subscriber_provider(
    result: Option<TrustListValidationSuccess>,
) -> Arc<dyn TrustListSubscriberProvider> {
    let mut subscriber = MockTrustListSubscriber::new();
    subscriber
        .expect_validate_subscription()
        .returning(move |_, _| {
            result.clone().ok_or(TrustListSubscriberError::MappingError(
                "test error".to_string(),
            ))
        });
    let subscriber = Arc::new(subscriber);
    let mut subscriber_provider = MockTrustListSubscriberProvider::new();
    subscriber_provider
        .expect_get()
        .returning(move |_| Some(subscriber.clone()));
    Arc::new(subscriber_provider)
}
