use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum VerifierProviderClientError {
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for VerifierProviderClientError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
