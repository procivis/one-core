use thiserror::Error;

use crate::{model::proof::ProofId, service::error::ErrorCode};

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
    Db(anyhow::Error),

    #[error("Missing required relation {relation} for {id}")]
    MissingRequiredRelation { relation: &'static str, id: String },

    #[error("Mismatch in size for claims list: expected {expected} claims, got {got}")]
    IncompleteClaimsList { expected: usize, got: usize },

    #[error("Mismatch in size for claim schema list: expected {expected} claims, got {got}")]
    IncompleteClaimsSchemaList { expected: usize, got: usize },

    #[error("Missing proof state for proof: {proof}")]
    MissingProofState { proof: ProofId },
}

impl DataLayerError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            DataLayerError::Db(_) => ErrorCode::Database,
            DataLayerError::AlreadyExists
            | DataLayerError::IncorrectParameters
            | DataLayerError::RecordNotUpdated
            | DataLayerError::MappingError
            | DataLayerError::IncompleteClaimsList { .. }
            | DataLayerError::IncompleteClaimsSchemaList { .. }
            | DataLayerError::MissingProofState { .. }
            | DataLayerError::MissingRequiredRelation { .. } => ErrorCode::Unmapped,
        }
    }
}

impl From<uuid::Error> for DataLayerError {
    fn from(_: uuid::Error) -> Self {
        Self::MappingError
    }
}
