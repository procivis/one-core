use std::sync::Arc;

use shared_types::{CredentialId, NotificationId, OrganisationId, ProofId, TaskId};

use crate::config::core_config::CoreConfig;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::credential::CredentialStateEnum;
use crate::model::proof::ProofStateEnum;
use crate::repository::notification_repository::NotificationRepository;

pub mod scheduler;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("URL host validation failed: `{0}`")]
    InvalidUrlHost(String),
    #[error("URL scheme validation failed: `{0}`")]
    InvalidUrlScheme(String),

    #[error("URL parse error: `{0}`")]
    UrlParse(#[from] url::ParseError),
    #[error("JSON error: `{0}`")]
    JSONSerialization(#[from] serde_json::Error),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::JSONSerialization(_) => ErrorCode::BR_0000,
            Self::InvalidUrlHost(_) => ErrorCode::BR_0369,
            Self::InvalidUrlScheme(_) => ErrorCode::BR_0370,
            Self::UrlParse(_) => ErrorCode::BR_0371,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum NotificationPayload {
    Credential(CredentialId, CredentialStateEnum),
    Proof(ProofId, ProofStateEnum),
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait NotificationScheduler: Send + Sync {
    /// Schedule notification to be sent
    async fn schedule(
        &self,
        url: &str,
        payload: NotificationPayload,
        r#type: TaskId,
        organisation_id: OrganisationId,
        history_target: Option<String>,
    ) -> Result<NotificationId, Error>;

    /// Perform validations for webhook URL
    fn validate_url(&self, url: &str, r#type: &TaskId) -> Result<(), Error>;
}

#[derive(Clone)]
pub(crate) struct NotificationSchedulerImpl {
    notification_repository: Arc<dyn NotificationRepository>,
    config: Arc<CoreConfig>,
}

impl NotificationSchedulerImpl {
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
