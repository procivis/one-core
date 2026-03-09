use std::string::FromUtf8Error;

use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::mapper::x509::CertificateParsingError;

#[derive(Debug, Error)]
pub enum TrustListPublisherError {
    #[error("Publication not found: `{0}`")]
    PublicationNotFound(String),
    #[error("Invalid identifier: `{0}`")]
    InvalidIdentifier(String),
    #[error("Unsupported role: `{0}`")]
    UnsupportedRole(String),
    #[error("Missing relation: `{0}`")]
    MissingRelation(String),
    #[error("Signing error: `{0}`")]
    Signing(String),
    #[error("Invalid JWS: `{0}`")]
    InvalidJws(String),

    #[error("Invalid params: `{0}`")]
    InvalidParams(serde_json::Error),

    #[error("JSON error: `{0}`")]
    Json(#[from] serde_json::Error),
    #[error("Certificate parsing error: `{0}`")]
    CertificateParsing(#[from] CertificateParsingError),
    #[error("Encoding error: `{0}`")]
    Encoding(#[from] ct_codecs::Error),
    #[error("UTF-8 error: `{0}`")]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("Datetime format error: `{0}`")]
    DatetimeFormat(#[from] time::error::Format),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for TrustListPublisherError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::PublicationNotFound(_) => ErrorCode::BR_0383,
            Self::InvalidIdentifier(_) => ErrorCode::BR_0382,
            Self::InvalidParams(_) => ErrorCode::BR_0385,
            Self::UnsupportedRole(_) => ErrorCode::BR_0386,
            Self::Nested(nested) => nested.error_code(),
            Self::MissingRelation(_)
            | Self::Json(_)
            | Self::CertificateParsing(_)
            | Self::Encoding(_)
            | Self::FromUtf8Error(_)
            | Self::DatetimeFormat(_)
            | Self::Signing(_)
            | Self::InvalidJws(_) => ErrorCode::BR_0384,
        }
    }
}
