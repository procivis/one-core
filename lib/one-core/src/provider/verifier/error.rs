use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum VerifierProviderError {
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for VerifierProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
