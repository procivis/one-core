use std::sync::Arc;

use shared_types::{NotificationId, OrganisationId, TaskId};
use url::Url;

use crate::config::core_config::CoreConfig;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::repository::notification_repository::NotificationRepository;

pub mod scheduler;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("URL host validation failed: `{0}`")]
    InvalidUrlHost(String),
    #[error("URL scheme validation failed: `{0}`")]
    InvalidUrlScheme(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidUrlHost(_) => ErrorCode::BR_0369,
            Self::InvalidUrlScheme(_) => ErrorCode::BR_0370,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

#[expect(unused)]
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait NotificationScheduler: Send + Sync {
    /// Schedule notification to be sent
    async fn schedule(
        &self,
        url: Url,
        payload: Vec<u8>,
        r#type: TaskId,
        organisation_id: OrganisationId,
        history_target: Option<String>,
    ) -> Result<NotificationId, Error>;
}

#[expect(unused)]
#[derive(Clone)]
pub(crate) struct NotificationSchedulerImpl {
    notification_repository: Arc<dyn NotificationRepository>,
    config: Arc<CoreConfig>,
}

impl NotificationSchedulerImpl {
    #[expect(unused)]
    pub(crate) fn new(
        notification_repository: Arc<dyn NotificationRepository>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            notification_repository,
            config,
        }
    }
}
