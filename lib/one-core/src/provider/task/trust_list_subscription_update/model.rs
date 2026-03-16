use url::ParseError;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::history::{HistoryAction, HistoryMetadata};
use crate::model::trust_list_subscription::TrustListSubscriptionState;

pub(super) enum NewState {
    Active,
    Error(Box<dyn ErrorCodeMixin + 'static>),
}

impl<T: ErrorCodeMixin + 'static> From<T> for NewState {
    fn from(value: T) -> Self {
        Self::Error(Box::new(value))
    }
}

impl NewState {
    pub fn action(&self) -> HistoryAction {
        match self {
            NewState::Active => HistoryAction::Reactivated,
            NewState::Error(_) => HistoryAction::Errored,
        }
    }
    pub fn state(&self) -> TrustListSubscriptionState {
        match self {
            NewState::Active => TrustListSubscriptionState::Active,
            NewState::Error(_) => TrustListSubscriptionState::Error,
        }
    }

    pub fn metadata(self) -> Option<HistoryMetadata> {
        match self {
            NewState::Error(error) => Some(error.into()),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TrustListSubscriptionUpdateTaskError {
    #[error("Invalid reference `{0}`")]
    InvalidReference(#[from] ParseError),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for TrustListSubscriptionUpdateTaskError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidReference(_) => ErrorCode::BR_0399,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
