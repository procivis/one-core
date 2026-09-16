use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub(crate) enum WalletProviderError {
    #[error("Could not verify proof: `{0}`")]
    CouldNotVerifyProof(String),
    #[error("Invalid config: {0}")]
    InvalidConfig(String),

    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for WalletProviderError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::CouldNotVerifyProof(_) => ErrorCode::BR_0071,
            Self::InvalidConfig(_) => ErrorCode::BR_0051,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
