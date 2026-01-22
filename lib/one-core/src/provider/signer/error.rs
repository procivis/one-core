use std::error::Error;

use shared_types::IdentifierId;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("Invalid issuer identifier {0}")]
    InvalidIssuerIdentifier(IdentifierId),
    #[error("Invalid signature payload: {0}")]
    InvalidPayload(Box<dyn Error + Send + Sync + 'static>),
    #[error("Cannot find key algorithm `{0}`")]
    MissingKeyAlgorithmProvider(String),
    #[error("Cannot find key storage `{0}`")]
    MissingKeyStorageProvider(String),
    #[error("Validity boundary `{validity_boundary}` is in the past")]
    ValidityBoundaryInThePast { validity_boundary: OffsetDateTime },
    #[error("Validity start `{validity_start}` is after validity end `{validity_end}`")]
    ValidityStartAfterEnd {
        validity_start: OffsetDateTime,
        validity_end: OffsetDateTime,
    },
    #[error(
        "Validity period from `{validity_start}` to `{validity_end}` is longer than the max allowed duration of {max_duration}"
    )]
    ValidityPeriodTooLong {
        validity_start: OffsetDateTime,
        validity_end: OffsetDateTime,
        max_duration: Duration,
    },
    #[error("Failed to sign: {0}")]
    SigningError(Box<dyn Error + Send + Sync + 'static>),
    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl SignerError {
    pub fn signing_error(e: impl Error + Send + Sync + 'static) -> Self {
        Self::SigningError(Box::new(e))
    }
}

impl From<serde_json::Error> for SignerError {
    fn from(e: serde_json::Error) -> Self {
        Self::InvalidPayload(Box::new(e))
    }
}

impl ErrorCodeMixin for SignerError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidPayload(_) => ErrorCode::BR_0332,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::MissingKeyStorageProvider(_) => ErrorCode::BR_0040,
            Self::MissingKeyAlgorithmProvider(_) => ErrorCode::BR_0042,
            Self::ValidityBoundaryInThePast { .. }
            | Self::ValidityStartAfterEnd { .. }
            | Self::ValidityPeriodTooLong { .. } => ErrorCode::BR_0324,
            Self::SigningError(_) => ErrorCode::BR_0329,
            Self::InvalidIssuerIdentifier(_) => ErrorCode::BR_0330,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
