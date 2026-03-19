use shared_types::IdentifierId;
use thiserror::Error;
use x509_parser::error::X509Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::identifier::IdentifierType;

#[derive(Debug, Error)]
pub enum TrustListSubscriberError {
    #[error("Ambiguous trust resolution, identifier {0} has multiple active certificates")]
    MultipleActiveCertificates(IdentifierId),
    #[error("Invalid trust list content: {0}")]
    InvalidContent(Box<dyn std::error::Error + Send + Sync>),
    #[error("Trust list role was not provided and is not specified by resolved list")]
    UnknownTrustListRole,
    #[error("Encoding error: `{0}`")]
    Encoding(#[from] ct_codecs::Error),
    #[error("Model mapping error: `{0}`")]
    MappingError(String),
    #[error("Unsupported identifier type: {0}")]
    UnsupportedIdentifierType(IdentifierType),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl From<serde_json::Error> for TrustListSubscriberError {
    fn from(err: serde_json::Error) -> Self {
        TrustListSubscriberError::InvalidContent(Box::new(err))
    }
}

impl From<X509Error> for TrustListSubscriberError {
    fn from(err: X509Error) -> Self {
        TrustListSubscriberError::InvalidContent(Box::new(err))
    }
}

impl From<asn1_rs::Err<X509Error>> for TrustListSubscriberError {
    fn from(err: asn1_rs::Err<X509Error>) -> Self {
        TrustListSubscriberError::InvalidContent(Box::new(err))
    }
}

impl ErrorCodeMixin for TrustListSubscriberError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidContent(_) => ErrorCode::BR_0393,
            Self::MultipleActiveCertificates(_) => ErrorCode::BR_0394,
            Self::UnknownTrustListRole | Self::MappingError(_) => ErrorCode::BR_0047,
            Self::UnsupportedIdentifierType(_) => ErrorCode::BR_0396,
            Self::Encoding(_) => ErrorCode::BR_0397,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
