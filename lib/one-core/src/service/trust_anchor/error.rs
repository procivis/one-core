use shared_types::TrustAnchorId;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(thiserror::Error, Debug)]
pub enum TrustAnchorServiceError {
    #[error("Trust anchor `{0}` not found")]
    NotFound(TrustAnchorId),
    #[error("Trust anchor name already in use")]
    AlreadyExists,

    #[error("Trust anchor type not found")]
    UnknownType,
    #[error("Trust anchor invalid request: {0}")]
    InvalidCreateRequest(String),
    #[error("Trust anchor type is not SIMPLE_TRUST_LIST")]
    TypeIsNotSimpleTrustList,

    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for TrustAnchorServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::BR_0115,
            Self::AlreadyExists => ErrorCode::BR_0113,
            Self::UnknownType => ErrorCode::BR_0114,
            Self::InvalidCreateRequest(_) => ErrorCode::BR_0177,
            Self::TypeIsNotSimpleTrustList => ErrorCode::BR_0122,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
