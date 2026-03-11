use shared_types::{InteractionId, ProofId};
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;

#[derive(Debug, Error)]
pub enum OID4VPDraft25ServiceError {
    #[error("Proof `{0}` not found")]
    MissingProof(ProofId),
    #[error("Missing proof for interaction `{0}`")]
    MissingProofForInteraction(InteractionId),
    #[error("Validation error: `{0}`")]
    ValidationError(String),

    #[error("OpenID4VC validation error `{0}`")]
    OpenID4VCError(#[from] OpenID4VCError),

    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for OID4VPDraft25ServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingProof(_) => ErrorCode::BR_0012,
            Self::MissingProofForInteraction(_) => ErrorCode::BR_0094,
            Self::ValidationError(_) => ErrorCode::BR_0323,
            Self::OpenID4VCError(_) => ErrorCode::BR_0048,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
