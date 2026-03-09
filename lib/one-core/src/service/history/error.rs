use shared_types::HistoryId;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(thiserror::Error, Debug)]
pub enum HistoryServiceError {
    #[error("History entry `{0}` not found")]
    NotFound(HistoryId),

    #[error("Invalid history source")]
    InvalidSource,

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for HistoryServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::BR_0100,
            Self::InvalidSource => ErrorCode::BR_0315,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
