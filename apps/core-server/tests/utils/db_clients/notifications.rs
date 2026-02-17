use std::sync::Arc;

use one_core::model::notification::Notification;
use one_core::repository::notification_repository::NotificationRepository;
use shared_types::{NotificationId, OrganisationId, TaskId};
use time::OffsetDateTime;
use uuid::Uuid;

pub struct NotificationsDB {
    repository: Arc<dyn NotificationRepository>,
}

#[derive(Default)]
pub struct TestingNotificationParams {
    pub id: Option<NotificationId>,
    pub url: Option<String>,
    pub payload: Option<Vec<u8>>,
    pub created_date: Option<OffsetDateTime>,
    pub next_try_date: Option<OffsetDateTime>,
    pub tries_count: Option<u32>,
    pub r#type: Option<TaskId>,
    pub history_target: Option<String>,
}

impl NotificationsDB {
    pub fn new(repository: Arc<dyn NotificationRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        organisation_id: OrganisationId,
        params: TestingNotificationParams,
    ) -> Notification {
        let notification = Notification {
            id: params.id.unwrap_or(Uuid::new_v4().into()),
            url: params.url.unwrap_or("url".to_string()),
            payload: params.payload.unwrap_or_default(),
            created_date: params.created_date.unwrap_or(OffsetDateTime::now_utc()),
            next_try_date: params.next_try_date.unwrap_or(OffsetDateTime::now_utc()),
            tries_count: params.tries_count.unwrap_or_default(),
            r#type: params.r#type.unwrap_or("type".into()),
            history_target: params.history_target,
            organisation_id,
        };

        self.repository
            .create(notification.to_owned())
            .await
            .unwrap();

        notification
    }

    pub async fn get(&self, id: impl Into<NotificationId>) -> Option<Notification> {
        self.repository.get(&id.into(), None).await.unwrap()
    }
}
