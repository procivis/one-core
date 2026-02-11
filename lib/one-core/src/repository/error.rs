use shared_types::{ClaimId, ClaimSchemaId, ProofId};
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin};

#[derive(Debug, Error)]
pub enum DataLayerError {
    #[error("Already exists")]
    AlreadyExists,

    #[error("Wrong parameters")]
    IncorrectParameters,

    #[error("Record not updated")]
    RecordNotUpdated,

    #[error("Response could not be mapped")]
    MappingError,

    #[error("Database error: {0}")]
    Db(#[from] anyhow::Error),

    #[error("UUID error: {0}")]
    UUIDError(#[from] uuid::Error),

    #[error("Missing required relation {relation} for {id}")]
    MissingRequiredRelation { relation: &'static str, id: String },

    #[error("Mismatch in size for claims list: expected {expected} claims, got {got}")]
    IncompleteClaimsList { expected: usize, got: usize },

    #[error("Mismatch in size for claim schema list: expected {expected} claims, got {got}")]
    IncompleteClaimsSchemaList { expected: usize, got: usize },

    #[error("Missing claim schema `{0}` for claim `{1}`")]
    MissingClaimsSchemaForClaim(ClaimSchemaId, ClaimId),

    #[error("Missing proof state for proof: {proof}")]
    MissingProofState { proof: ProofId },

    #[error("Transaction error: {0}")]
    TransactionError(String),
}

impl ErrorCodeMixin for DataLayerError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Db(_) => ErrorCode::BR_0054,
            Self::AlreadyExists => ErrorCode::BR_0357,
            Self::IncorrectParameters
            | Self::RecordNotUpdated
            | Self::MappingError
            | Self::UUIDError(_)
            | Self::IncompleteClaimsList { .. }
            | Self::IncompleteClaimsSchemaList { .. }
            | Self::MissingProofState { .. }
            | Self::MissingRequiredRelation { .. }
            | Self::MissingClaimsSchemaForClaim(_, _)
            | Self::TransactionError(_) => ErrorCode::BR_0000,
        }
    }
}
