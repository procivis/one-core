use std::sync::Arc;

use model::WebhookNotifyParams;
use serde_json::Value;
use shared_types::TaskId;

use self::dto::WebhookNotificationResultDTO;
use super::Task;
use crate::error::ContextWithErrorCode;
use crate::model::common::SortDirection;
use crate::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use crate::model::list_query::ListSorting;
use crate::model::notification::{
    Notification, NotificationFilterValue, NotificationListQuery, SortableNotificationColumn,
};
use crate::proto::notification_sender::{NotificationResult, NotificationSender};
use crate::repository::notification_repository::NotificationRepository;
use crate::service::error::ServiceError;

pub mod dto;
pub mod model;

pub(crate) struct WebhookNotify {
    id: TaskId,
    params: WebhookNotifyParams,
    notification_repository: Arc<dyn NotificationRepository>,
    notification_sender: Arc<dyn NotificationSender>,
}

impl WebhookNotify {
    pub fn new(
        id: TaskId,
        params: WebhookNotifyParams,
        notification_repository: Arc<dyn NotificationRepository>,
        notification_sender: Arc<dyn NotificationSender>,
    ) -> Self {
        Self {
            id,
            params,
            notification_repository,
            notification_sender,
        }
    }
}

#[async_trait::async_trait]
impl Task for WebhookNotify {
    async fn run(&self, _params: Option<Value>) -> Result<Value, ServiceError> {
        let notifications = self
            .notification_repository
            .list(NotificationListQuery {
                filtering: Some(
                    NotificationFilterValue::Types(vec![self.id.to_owned()]).condition()
                        & NotificationFilterValue::NextTryDate(ValueComparison {
                            comparison: ComparisonType::LessThanOrEqual,
                            value: crate::clock::now_utc(),
                        }),
                ),
                sorting: Some(ListSorting {
                    column: SortableNotificationColumn::CreatedDate,
                    direction: Some(SortDirection::Ascending),
                }),
                ..Default::default()
            })
            .await
            .error_while("listing notifications")?
            .values;

        let mut result = WebhookNotificationResultDTO {
            delivered: vec![],
            failed: vec![],
            rescheduled: vec![],
        };

        for Notification { id, .. } in notifications {
            let notification_result = self
                .notification_sender
                .send_notification(id, self.params.clone())
                .await;
            match notification_result {
                // unexpected failures
                Err(err) => tracing::warn!("Failed to process notification: {err}"),
                Ok(delivery_result) => {
                    match delivery_result {
                        NotificationResult::Delivered => {
                            result.delivered.push(id);
                        }
                        // Expected failures
                        NotificationResult::Failed => {
                            result.failed.push(id);
                        }
                        NotificationResult::Rescheduled => {
                            result.rescheduled.push(id);
                        }
                    };
                }
            }
        }

        serde_json::to_value(result).map_err(|e| ServiceError::MappingError(e.to_string()))
    }
}
