use shared_types::{CertificateId, DidValue, IdentifierId, KeyId};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::did::KeyFilter;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("Invalid signature payload: {0}")]
    InvalidPayload(#[from] serde_json::Error),
    #[error("Identifier {0} not found")]
    IdentifierNotFound(IdentifierId),
    #[error("Key {0} not found")]
    KeyNotFound(KeyId),
    #[error("Did `{did}` does not contain a key matching filter `{filter:?}`")]
    NoMatchingKeyOnDid {
        filter: KeyFilter,
        did: Box<DidValue>,
    },
    #[error("Cannot find key algorithm `{0}`")]
    MissingKeyAlgorithmProvider(String),
    #[error("Certificate {0} not found")]
    CertificateNotFound(CertificateId),
    #[error("Certificate {0} is not active")]
    CertificateNotActive(CertificateId),
    #[error("No active certificate available for identifier {0}")]
    NoActiveCertificates(IdentifierId),
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
            Self::KeyNotFound(_) | Self::NoMatchingKeyOnDid { .. } => ErrorCode::BR_0037,
            Self::CertificateNotFound(_) => ErrorCode::BR_0223,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::MissingKeyAlgorithmProvider(_) => ErrorCode::BR_0042,
            Self::CertificateNotActive(_) | Self::NoActiveCertificates(_) => ErrorCode::BR_0000,
            Self::RevocationNotSupported => ErrorCode::BR_0101,
            Self::ValidityBoundaryInThePast { .. }
            | Self::ValidityStartAfterEnd { .. }
            | Self::ValidityPeriodTooLong { .. } => ErrorCode::BR_0324,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
