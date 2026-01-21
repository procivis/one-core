use shared_types::IdentifierId;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("Invalid signature payload: {0}")]
    InvalidPayload(#[from] serde_json::Error),
    #[error("Identifier {0} not found")]
    IdentifierNotFound(IdentifierId),
    #[error("Cannot find key algorithm `{0}`")]
    MissingKeyAlgorithmProvider(String),
    #[error("Revocation not supported")]
    RevocationNotSupported,
    #[error("Mapping error: {0}")]
    MappingError(String),
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
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for SignerError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidPayload(_) => ErrorCode::BR_0189,
            Self::IdentifierNotFound(_) => ErrorCode::BR_0207,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::MissingKeyAlgorithmProvider(_) => ErrorCode::BR_0042,
            Self::RevocationNotSupported => ErrorCode::BR_0101,
            Self::ValidityBoundaryInThePast { .. }
            | Self::ValidityStartAfterEnd { .. }
            | Self::ValidityPeriodTooLong { .. } => ErrorCode::BR_0324,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
