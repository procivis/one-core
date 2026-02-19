use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum StatisticsError {
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for StatisticsError {
    fn error_code(&self) -> ErrorCode {
        match self {
            StatisticsError::Nested(nested) => nested.error_code(),
        }
    }
}
