use std::sync::Arc;

use futures::FutureExt;
use num_traits::pow;
use shared_types::NotificationId;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::common::LockType;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryErrorMetadata, HistoryMetadata, HistorySource,
};
use crate::model::notification::UpdateNotificationRequest;
use crate::proto::http_client;
use crate::proto::http_client::{HttpClient, StatusCode};
use crate::proto::notification_scheduler::scheduler::validate_url;
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::proto::transaction_manager::{IsolationLevel, TransactionManager};
use crate::provider::task::webhook_notify::model::{Retries, WebhookNotifyParams};
use crate::repository::history_repository::HistoryRepository;
use crate::repository::notification_repository::NotificationRepository;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait NotificationSender: Send + Sync {
    async fn send_notification(
        &self,
        notification_id: NotificationId,
        params: WebhookNotifyParams,
    ) -> Result<NotificationResult, Error>;
}

#[derive(Debug, PartialEq)]
pub enum NotificationResult {
    Delivered,
    Rescheduled,
    Failed,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Notification {0} not found")]
    NotificationNotFound(NotificationId),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotificationNotFound(_) => ErrorCode::BR_0377,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

pub struct NotificationSenderImpl {
    history_repository: Arc<dyn HistoryRepository>,
    notification_repository: Arc<dyn NotificationRepository>,
    tx_manager: Arc<dyn TransactionManager>,
    client: Arc<dyn HttpClient>,
    session_provider: Arc<dyn SessionProvider>,
}

impl NotificationSenderImpl {
    pub fn new(
        history_repository: Arc<dyn HistoryRepository>,
        notification_repository: Arc<dyn NotificationRepository>,
        tx_manager: Arc<dyn TransactionManager>,
        client: Arc<dyn HttpClient>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            history_repository,
            notification_repository,
            tx_manager,
            client,
            session_provider,
        }
    }

    async fn send_request(
        &self,
        url: &str,
        payload: Vec<u8>,
        params: WebhookNotifyParams,
    ) -> Result<(NotificationResult, Option<HistoryMetadata>), Error> {
        validate_url(url, &params).error_while("validating notification URL")?;
        let response = async {
            Ok::<_, http_client::Error>(
                self.client
                    .post(url)
                    .header("Content-Type", "application/json")
                    .body(payload)
                    .timeout(params.request_timeout)
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

    async fn send_internal(
        &self,
        notification_id: NotificationId,
        params: WebhookNotifyParams,
    ) -> Result<NotificationResult, Error> {
        let notification = self
            .notification_repository
            .get(&notification_id, Some(LockType::Update))
            .await
            .error_while("getting notification")?
            .ok_or(Error::NotificationNotFound(notification_id))?;
        let retries = params.retries.clone();

        let (mut result, metadata) = self
            .send_request(&notification.url, notification.payload, params)
            .await?;
        let history_action = match result {
            NotificationResult::Delivered => Some(HistoryAction::Delivered),
            NotificationResult::Failed => Some(HistoryAction::Errored),
            NotificationResult::Rescheduled => {
                if let Some(param_retries) = &retries
                    && notification.tries_count < (param_retries.max_attempts - 1)
                {
                    self.notification_repository
                        .update(
                            &notification.id,
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
                    result = NotificationResult::Failed;
                    Some(HistoryAction::Errored)
                }
            }
        };

        if let Some(action) = history_action {
            // the final status of delivery known, so no more delivery retries later
            self.notification_repository
                .delete(&notification_id)
                .await
                .error_while("deleting notification")?;

            self.history_repository
                .create_history(History {
                    id: Uuid::new_v4().into(),
                    created_date: OffsetDateTime::now_utc(),
                    action,
                    name: "".to_string(),
                    target: notification.history_target,
                    source: HistorySource::Core,
                    entity_id: Some(notification.id.into()),
                    entity_type: HistoryEntityType::Notification,
                    metadata,
                    organisation_id: Some(notification.organisation_id),
                    user: self.session_provider.session().user(),
                })
                .await
                .error_while("creating history")?;
        }

        Ok(result)
    }
}

#[async_trait::async_trait]
impl NotificationSender for NotificationSenderImpl {
    async fn send_notification(
        &self,
        notification_id: NotificationId,
        params: WebhookNotifyParams,
    ) -> Result<NotificationResult, Error> {
        self.tx_manager
            .tx_with_config(
                self.send_internal(notification_id, params).boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await
            .error_while("processing notification")?
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
    use crate::provider::task::webhook_notify::model::Retries;

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
