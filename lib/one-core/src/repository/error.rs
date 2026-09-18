use std::convert::Infallible;

use shared_types::ProofId;
use thiserror::Error;
use uuid::Uuid;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityKind {
    Certificate,
    Credential,
    CredentialByClaim,
    CredentialSchema,
    CredentialSchemaFormat,
    Did,
    DidByValue,
    History,
    Identifier,
    IdentifierByDidId,
    Instance,
    Interaction,
    Key,
    ManagedInstance,
    ManagedInstanceAttestation,
    Notification,
    Organisation,
    Proof,
    ProofByInteraction,
    ProofSchema,
    RemoteEntityCache,
    RevocationList,
    RevocationListEntry,
    TrustCollection,
    TrustEntry,
    TrustListPublication,
    TrustListSubscription,
}

#[derive(Debug, Error)]
pub enum DataLayerError {
    #[error("Already exists")]
    AlreadyExists,

    #[error("{kind:?} `{id}` not found")]
    EntityNotFound { kind: EntityKind, id: Uuid },

    #[error("Wrong parameters")]
    IncorrectParameters,

    #[error("Record not updated")]
    RecordNotUpdated,

    #[error("Response could not be mapped")]
    MappingError,

    #[error("List response is missing counts")]
    MissingCount,

    #[error("Missing required relation {relation} for {id}")]
    MissingRequiredRelation { relation: &'static str, id: String },

    #[error("Mismatch in size for claims list: expected {expected} claims, got {got}")]
    IncompleteClaimsList { expected: usize, got: usize },

    #[error("Mismatch in size for claim schema list: expected {expected} claims, got {got}")]
    IncompleteClaimsSchemaList { expected: usize, got: usize },

    #[error("Missing proof state for proof: {proof}")]
    MissingProofState { proof: ProofId },

    #[error("Transaction error: {0}")]
    TransactionError(String),

    #[error("Database error: {0}")]
    Db(#[from] anyhow::Error),

    #[error("UUID error: {0}")]
    UUIDError(#[from] uuid::Error),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for DataLayerError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Db(_) => ErrorCode::BR_0054,
            Self::AlreadyExists => ErrorCode::BR_0357,
            Self::IncorrectParameters
            | Self::RecordNotUpdated
            | Self::MappingError
            | Self::MissingCount
            | Self::UUIDError(_)
            | Self::IncompleteClaimsList { .. }
            | Self::IncompleteClaimsSchemaList { .. }
            | Self::MissingProofState { .. }
            | Self::MissingRequiredRelation { .. }
            | Self::TransactionError(_) => ErrorCode::BR_0000,
            Self::EntityNotFound { kind, .. } => kind.error_code(),
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

impl EntityKind {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Certificate => ErrorCode::BR_0223,
            Self::Credential | Self::CredentialByClaim => ErrorCode::BR_0001,
            Self::CredentialSchema | Self::CredentialSchemaFormat => ErrorCode::BR_0006,
            Self::Did | Self::DidByValue => ErrorCode::BR_0024,
            Self::History => ErrorCode::BR_0100,
            Self::Identifier | Self::IdentifierByDidId => ErrorCode::BR_0207,
            Self::Instance => ErrorCode::BR_0296,
            Self::Interaction => ErrorCode::BR_0257,
            Self::Key => ErrorCode::BR_0037,
            Self::ManagedInstance | Self::ManagedInstanceAttestation => ErrorCode::BR_0259,
            Self::Notification => ErrorCode::BR_0377,
            Self::Organisation => ErrorCode::BR_0022,
            Self::Proof | Self::ProofByInteraction => ErrorCode::BR_0012,
            Self::ProofSchema => ErrorCode::BR_0014,
            Self::RevocationList | Self::RevocationListEntry => ErrorCode::BR_0034,
            Self::TrustCollection => ErrorCode::BR_0391,
            Self::TrustEntry => ErrorCode::BR_0387,
            Self::TrustListPublication => ErrorCode::BR_0383,
            Self::TrustListSubscription => ErrorCode::BR_0402,
            Self::RemoteEntityCache => ErrorCode::BR_0354,
        }
    }
}

impl From<Infallible> for DataLayerError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}
