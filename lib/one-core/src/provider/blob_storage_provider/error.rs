use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum BlobStorageError {
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for BlobStorageError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
