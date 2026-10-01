use standardized_types::openid4vp::dcql::DcqlError;
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum VerificationProtocolError {
    #[error("Verification protocol failure: `{0}`")]
    Failed(String),
    #[error("Verification protocol disabled: `{0}`")]
    Disabled(String),
    #[error("Operation not supported")]
    OperationNotSupported,
    #[error("Invalid request: `{0}`")]
    InvalidRequest(String),
    #[error("Invalid request: `{0}`")]
    InvalidDcqlQueryOrPresentationDefinition(String),
    #[error("Interaction not allowed - untrusted")]
    Untrusted,
    #[error(transparent)]
    Other(anyhow::Error),
    #[error("Invalid transaction data assignment: `{0}`")]
    InvalidTransactionDataAssignment(String),
    #[error("Encryption failure: `{0}`")]
    EncryptionError(String),

    #[error("DCQL error: `{0}`")]
    DcqlError(#[from] DcqlError),
    #[error("JSON error: `{0}`")]
    Json(#[from] serde_json::Error),
    #[error("URL encoded error: `{0}`")]
    URLEncoded(#[from] serde_urlencoded::ser::Error),
    #[error("CBOR serialization: `{0}`")]
    CBORSerialization(#[from] ciborium::ser::Error<std::io::Error>),
    #[error("CBOR parsing: `{0}`")]
    CBORParsing(#[from] ciborium::de::Error<std::io::Error>),
    #[error("Encoding error: `{0}`")]
    Encoding(#[from] ct_codecs::Error),
    #[error("NDEF error: `{0}`")]
    Ndef(#[from] ndef_rs::error::NdefError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for VerificationProtocolError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Failed(_)
            | Self::Json(_)
            | Self::URLEncoded(_)
            | Self::OperationNotSupported
            | Self::Other(_)
            | Self::CBORSerialization(_)
            | Self::CBORParsing(_)
            | Self::Encoding(_)
            | Self::EncryptionError(_)
            | Self::Ndef(_) => ErrorCode::BR_0062,
            Self::InvalidTransactionDataAssignment(_) => ErrorCode::BR_0459,
            Self::Untrusted => ErrorCode::BR_0433,
            Self::InvalidDcqlQueryOrPresentationDefinition(_) => ErrorCode::BR_0083,
            Self::InvalidRequest(_) | Self::Disabled(_) | Self::DcqlError(_) => ErrorCode::BR_0085,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
