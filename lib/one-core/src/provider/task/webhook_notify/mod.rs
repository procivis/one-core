use std::sync::Arc;

use futures::FutureExt;
use model::{Retries, WebhookNotifyParams};
use num_traits::pow;
use serde_json::Value;
use shared_types::{NotificationId, TaskId};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use self::dto::WebhookNotificationResultDTO;
use super::Task;
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin};
use crate::model::common::{LockType, SortDirection};
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryErrorMetadata, HistoryMetadata, HistorySource,
};
use crate::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use crate::model::list_query::ListSorting;
use crate::model::notification::{
    Notification, NotificationFilterValue, NotificationListQuery, SortableNotificationColumn,
    UpdateNotificationRequest,
};
use crate::proto::http_client::{self, HttpClient, StatusCode};
use crate::proto::notification_scheduler::scheduler::validate_url;
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::proto::transaction_manager::{IsolationLevel, TransactionManager};
use crate::repository::history_repository::HistoryRepository;
use crate::repository::notification_repository::NotificationRepository;
use crate::service::error::ServiceError;

pub mod dto;
pub mod model;

pub(crate) struct WebhookNotify {
    id: TaskId,
    history_repository: Arc<dyn HistoryRepository>,
    notification_repository: Arc<dyn NotificationRepository>,
    tx_manager: Arc<dyn TransactionManager>,
    client: Arc<dyn HttpClient>,
    session_provider: Arc<dyn SessionProvider>,
    params: WebhookNotifyParams,
}

impl WebhookNotify {
    pub fn new(
        id: TaskId,
        history_repository: Arc<dyn HistoryRepository>,
        notification_repository: Arc<dyn NotificationRepository>,
        tx_manager: Arc<dyn TransactionManager>,
        client: Arc<dyn HttpClient>,
        session_provider: Arc<dyn SessionProvider>,
        params: WebhookNotifyParams,
    ) -> Self {
        Self {
            id,
            history_repository,
            notification_repository,
            tx_manager,
            client,
            session_provider,
            params,
        }
    }
}

#[async_trait::async_trait]
impl Task for WebhookNotify {
    async fn run(&self) -> Result<Value, ServiceError> {
        let notifications = self
            .notification_repository
            .list(NotificationListQuery {
                filtering: Some(
                    NotificationFilterValue::Types(vec![self.id.to_owned()]).condition()
                        & NotificationFilterValue::NextTryDate(ValueComparison {
                            comparison: ComparisonType::LessThanOrEqual,
                            value: OffsetDateTime::now_utc(),
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
            let msg = format!("processing notification {id}");
            let delivery_result = self
                .tx_manager
                .tx_with_config::<_, ServiceError>(
                    async { self.process_notification(id).await }.boxed(),
                    Some(IsolationLevel::ReadCommitted),
                    None,
                )
                .await
                .error_while(&msg)?
                .error_while(msg)?;

            match delivery_result {
                Some(NotificationResult::Delivered) => {
                    result.delivered.push(id);
                }
                Some(NotificationResult::Failed) => {
                    result.failed.push(id);
                }
                Some(NotificationResult::Rescheduled) => {
                    result.rescheduled.push(id);
                }
                None => {}
            };
        }

        serde_json::to_value(result).map_err(|e| ServiceError::MappingError(e.to_string()))
    }
}

#[derive(Debug, PartialEq)]
enum NotificationResult {
    Delivered,
    Rescheduled,
    Failed,
}

impl WebhookNotify {
    async fn process_notification(
        &self,
        notification_id: NotificationId,
    ) -> Result<Option<NotificationResult>, ServiceError> {
        let notification = self
            .notification_repository
            .get(&notification_id, Some(LockType::Update))
            .await
            .error_while("getting notification")?;

        let Some(notification) = notification else {
            tracing::warn!("Notification {notification_id} not found");
            return Ok(None);
        };

        let (result, metadata) = self
            .send_notification(&notification.url, notification.payload)
            .await?;

        let history_action = match result {
            NotificationResult::Rescheduled => {
                if let Some(param_retries) = &self.params.retries
                    && notification.tries_count < (param_retries.max_attempts - 1)
                {
                    self.notification_repository
                        .update(
                            &notification_id,
                            UpdateNotificationRequest {
                                tries_count: Some(notification.tries_count + 1),
                                next_try_date: Some(calculate_next_try_date(
                                    notification.next_try_date,
                                    notification.tries_count as _,
                                    param_retries,
                                )),
                            },
                        )
                        .await
                        .error_while("updating notification")?;

                    None
                } else {
                    tracing::warn!("Max retries reached");
                    Some(HistoryAction::Errored)
                }
            }

            NotificationResult::Delivered | NotificationResult::Failed => {
                self.notification_repository
                    .delete(&notification_id)
                    .await
                    .error_while("deleting notification")?;

                Some(if result == NotificationResult::Delivered {
                    HistoryAction::Delivered
                } else {
                    HistoryAction::Errored
                })
            }
        };

        if let Some(action) = history_action {
            self.history_repository
                .create_history(History {
                    id: Uuid::new_v4().into(),
                    created_date: OffsetDateTime::now_utc(),
                    action,
                    name: "".to_string(),
                    target: notification.history_target,
                    source: HistorySource::Core,
                    entity_id: Some(notification_id.into()),
                    entity_type: HistoryEntityType::Notification,
                    metadata,
                    organisation_id: Some(notification.organisation_id),
                    user: self.session_provider.session().user(),
                })
                .await
                .error_while("creating history")?;
        }

        Ok(Some(result))
    }

    async fn send_notification(
        &self,
        url: &str,
        payload: Vec<u8>,
    ) -> Result<(NotificationResult, Option<HistoryMetadata>), ServiceError> {
        if let Err(e) = self.validate_url(url) {
            tracing::warn!(%e, "Error validating notification URL");
            return Ok((
                NotificationResult::Failed,
                Some(HistoryMetadata::ErrorMetadata(HistoryErrorMetadata {
                    error_code: e.error_code(),
                    message: e.to_string(),
                })),
            ));
        }

        let response = async {
            Ok::<_, http_client::Error>(
                self.client
                    .post(url)
                    .body(payload)
                    .timeout(self.params.request_timeout)
                    .send()
                    .await?
                    .status,
            )
        }
        .await;

        let (result, metadata) = match response {
            Ok(status_code) if status_code.is_success() => (NotificationResult::Delivered, None),
            Ok(status_code) if status_code.is_server_error() || status_code == StatusCode(404) => {
                tracing::info!("Notification failure, HTTP status code: {status_code}");
                (
                    NotificationResult::Rescheduled,
                    Some(history_metadata_from_status_code(status_code)),
                )
            }
            Err(e) => {
                tracing::info!(%e, "Notification request failure");
                (
                    NotificationResult::Rescheduled,
                    Some(HistoryMetadata::ErrorMetadata(HistoryErrorMetadata {
                        error_code: e.error_code(),
                        message: e.to_string(),
                    })),
                )
            }
            Ok(status_code) => {
                tracing::warn!("Notification failure, HTTP status code: {status_code}");
                (
                    NotificationResult::Failed,
                    Some(history_metadata_from_status_code(status_code)),
                )
            }
        };

        Ok((result, metadata))
    }

    fn validate_url(&self, url: &str) -> Result<(), ServiceError> {
        let url = Url::parse(url).map_err(|e| ServiceError::MappingError(e.to_string()))?;
        Ok(validate_url(&url, &self.params).error_while("validating notification URL")?)
    }
}

fn history_metadata_from_status_code(status_code: StatusCode) -> HistoryMetadata {
    HistoryMetadata::ErrorMetadata(HistoryErrorMetadata {
        error_code: ErrorCode::BR_0347,
        message: format!("HTTP status: {status_code}"),
    })
}

fn calculate_next_try_date(
    previous_scheduled_time: OffsetDateTime,
    already_tried_times: usize,
    params: &Retries,
) -> OffsetDateTime {
    let factor = pow(params.exponential_factor, already_tried_times);
    let delay = params.interval.as_seconds_f32() * factor;
    previous_scheduled_time + Duration::seconds_f32(delay)
}

#[cfg(test)]
mod tests {
    use time::{Duration, OffsetDateTime};

    use super::calculate_next_try_date;
    use super::model::Retries;

    #[test]
    fn test_calculate_next_try_date() {
        let params = Retries {
            interval: Duration::minutes(1),
            max_attempts: 10,
            exponential_factor: 2.0,
        };

        let now = OffsetDateTime::now_utc();

        assert_time_equal(
            calculate_next_try_date(now, 0, &params),
            now + Duration::minutes(1),
        );

        assert_time_equal(
            calculate_next_try_date(now, 1, &params),
            now + Duration::minutes(2),
        );

        assert_time_equal(
            calculate_next_try_date(now, 2, &params),
            now + Duration::minutes(4),
        );
    }

    fn assert_time_equal(time1: OffsetDateTime, time2: OffsetDateTime) {
        let diff = Duration::nanoseconds(
            (time1.unix_timestamp_nanos() - time2.unix_timestamp_nanos()).abs() as i64,
        );
        assert!(
            diff <= Duration::milliseconds(1),
            "Too big difference: {time1} - {time2}"
        )
    }
}
