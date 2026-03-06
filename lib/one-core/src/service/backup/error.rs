use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(thiserror::Error, Debug)]
pub enum BackupServiceError {
    #[error("Invalid path: `{0}`")]
    InvalidPath(String),
    #[error("Checksum mismatch")]
    ChecksumMismatch,

    #[error("Hash error: `{0}`")]
    Hash(#[from] one_crypto::HasherError),
    #[error("I/O error: `{0}`")]
    IO(#[from] std::io::Error),
    #[error("Zip error: `{0}`")]
    Zip(#[from] zip::result::ZipError),
    #[error("JSON serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error("Encryption error: `{error}` while: {operation}")]
    Encryption {
        error: one_crypto::encryption::EncryptionError,
        operation: &'static str,
    },

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for BackupServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::InvalidPath(_)
            | Self::ChecksumMismatch
            | Self::IO(_)
            | Self::Zip(_)
            | Self::SerdeJson(_)
            | Self::Hash(_)
            | Self::Encryption { .. } => ErrorCode::BR_0000,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
