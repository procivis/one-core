use std::string::FromUtf8Error;

use shared_types::InteractionId;
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;

#[derive(Debug, Error)]
pub enum OID4VPFinal1_0ServiceError {
    #[error("Missing proof for interaction `{0}`")]
    MissingProofForInteraction(InteractionId),
    #[error("Validation error: `{0}`")]
    ValidationError(String),
    #[error("Missing interaction data")]
    MissingInteractionData,
    #[error("JSON error: `{0}`")]
    JsonError(#[from] serde_json::Error),
    #[error("From UTF-8 error: `{0}`")]
    FromUtf8Error(#[from] FromUtf8Error),

    #[error("OpenID4VC validation error `{0}`")]
    OpenID4VCError(#[from] OpenID4VCError),

    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for OID4VPFinal1_0ServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingProofForInteraction(_) => ErrorCode::BR_0094,
            Self::ValidationError(_) => ErrorCode::BR_0323,
            Self::OpenID4VCError(_) => ErrorCode::BR_0048,
            Self::MappingError(_)
            | Self::MissingInteractionData
            | Self::FromUtf8Error(_)
            | Self::JsonError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
