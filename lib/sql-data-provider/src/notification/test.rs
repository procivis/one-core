use one_core::model::list_filter::ListFilterValue;
use one_core::model::list_query::ListPagination;
use one_core::model::notification::{
    Notification, NotificationFilterValue, NotificationListQuery, UpdateNotificationRequest,
};
use one_core::model::organisation::Organisation;
use one_core::repository::notification_repository::NotificationRepository;
use sea_orm::{ActiveModelTrait, Set};
use shared_types::NotificationId;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use time::macros::datetime;
use uuid::Uuid;

use super::NotificationProvider;
use crate::entity::notification;
use crate::test_utilities::{
    dummy_organisation, insert_organisation_to_database, setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub notification_id: NotificationId,
    pub organisation: Organisation,
    pub provider: NotificationProvider,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    let now = OffsetDateTime::now_utc();
    let organisation = dummy_organisation(Some(organisation_id));

    let notification_id = Uuid::new_v4().into();
    notification::ActiveModel {
        id: Set(notification_id),
        url: Set("url".to_string()),
        payload: Set(vec![]),
        created_date: Set(now),
        next_try_date: Set(now),
        tries_count: Set(0),
        r#type: Set("type".into()),
        history_target: Set(None),
        organisation_id: Set(organisation_id),
    }
    .insert(&db)
    .await
    .unwrap();

    let provider = NotificationProvider {
        db: TransactionManagerImpl::new(db),
    };

    TestSetup {
        notification_id,
        organisation,
        provider,
    }
}

#[tokio::test]
async fn test_create_notification_success() {
    let TestSetup {
        organisation,
        provider,
        ..
    } = setup().await;

    let now = OffsetDateTime::now_utc();

    let id = Uuid::new_v4().into();
    let result = provider
        .create(Notification {
            id,
            url: "url".to_string(),
            payload: vec![],
            created_date: now,
            next_try_date: now,
            tries_count: 0,
            r#type: "type".into(),
            history_target: None,
            organisation_id: organisation.id,
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(id, result.unwrap());
}

#[tokio::test]
async fn test_get_notification_success() {
    let TestSetup {
        notification_id,
        provider,
        ..
    } = setup().await;

    let result = provider.get(&notification_id, None).await.unwrap().unwrap();

    assert_eq!(notification_id, result.id);
}

#[tokio::test]
async fn test_get_notification_list_success() {
    let TestSetup {
        notification_id,
        provider,
        ..
    } = setup().await;

    let query = NotificationListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 1,
        }),
        filtering: Some(NotificationFilterValue::Types(vec!["type".into()]).condition()),
        ..Default::default()
    };

    let result = provider.list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages, 1);
    assert_eq!(data.total_items, 1);
    assert_eq!(data.values.len(), 1);

    assert_eq!(data.values[0].id, notification_id);
}

#[tokio::test]
async fn test_update_notification() {
    let TestSetup {
        notification_id,
        provider,
        ..
    } = setup().await;

    let date = datetime!(2025-08-11 09:31:29 UTC);

    provider
        .update(
            &notification_id,
            UpdateNotificationRequest {
                tries_count: Some(1),
                next_try_date: Some(date),
            },
        )
        .await
        .unwrap();

    let updated = provider.get(&notification_id, None).await.unwrap().unwrap();
    assert_eq!(updated.tries_count, 1);
    assert_eq!(updated.next_try_date, date);
}

#[tokio::test]
async fn test_delete_notification() {
    let TestSetup {
        notification_id,
        provider,
        ..
    } = setup().await;

    let result = provider.delete(&notification_id).await;

    assert!(result.is_ok());

    let result = provider.get(&notification_id, None).await.unwrap();

    assert!(result.is_none());
}
