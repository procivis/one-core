use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(thiserror::Error, Debug)]
pub enum NfcServiceError {
    #[error("Missing configuration for verification engagement type: {0}")]
    MissingVerificationEngagementConfig(String),

    #[error("NFC not available")]
    NotAvailable,

    #[error("Failed to parse NFC data structure: {0}")]
    ParsingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for NfcServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingVerificationEngagementConfig(_) => ErrorCode::BR_0077,
            Self::NotAvailable => ErrorCode::BR_0274,
            Self::ParsingError(_) => ErrorCode::BR_0000,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
