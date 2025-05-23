use shared_types::{ClaimId, ClaimSchemaId, ProofId};
use thiserror::Error;

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
}

impl From<uuid::Error> for DataLayerError {
    fn from(_: uuid::Error) -> Self {
        Self::MappingError
    }
}
