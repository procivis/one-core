use shared_types::{DidId, DidValue};
use thiserror::Error;

use crate::config::ConfigValidationError;
use crate::crypto::error::CryptoProviderError;
use crate::model::claim_schema::ClaimSchemaId;
use crate::model::credential::{CredentialId, CredentialStateEnum};
use crate::model::proof::ProofStateEnum;
use crate::service::oidc::dto::OpenID4VCIError;
use crate::{
    provider::credential_formatter::error::FormatterError,
    provider::did_method::DidMethodError,
    provider::transport_protocol::TransportProtocolError,
    repository::error::DataLayerError,
    util::{bitstring::BitstringError, oidc::FormatError},
};

use super::did::DidDeactivationError;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("General repository error `{0}`")]
    GeneralRuntimeError(String),
    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error("Not updated")]
    NotUpdated,
    #[error("Validation error: `{0}`")]
    ValidationError(String),
    #[error("OpenID4VCI validation error `{0}`")]
    OpenID4VCError(#[from] OpenID4VCIError),
    #[error("Config validation error `{0}`")]
    ConfigValidationError(#[from] ConfigValidationError),
    #[error("Transport protocol error `{0}`")]
    TransportProtocolError(#[from] TransportProtocolError),
    #[error("Formatter error `{0}`")]
    FormatterError(#[from] FormatterError),
    #[error("Bitstring error `{0}`")]
    BitstringError(#[from] BitstringError),
    #[error("Missing signer for algorithm `{0}`")]
    MissingSigner(String),
    #[error("Missing algorithm `{0}`")]
    MissingAlgorithm(String),
    #[error("Missing transport protocol `{0}`")]
    MissingTransportProtocol(String),
    #[error("Key algorithm error `{0}`")]
    KeyAlgorithmError(String),
    #[error("Did method error `{0}`")]
    DidMethodError(#[from] DidMethodError),
    #[error("Crypto provider error: `{0}`")]
    CryptoError(#[from] CryptoProviderError),
    #[error("Other Repository error: `{0}`")]
    Other(String),

    #[error(transparent)]
    EntityNotFound(#[from] EntityNotFoundError),
    #[error("Not found")]
    NotFound,

    #[error(transparent)]
    BusinessLogic(#[from] BusinessLogicError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Repository(DataLayerError),
    #[error("Response mapping error: {0}")]
    ResponseMapping(String),
}

#[derive(Debug, thiserror::Error)]
pub enum EntityNotFoundError {
    #[error("Credential `{0}` not found")]
    Credential(CredentialId),

    #[error("Did `{0}` not found")]
    Did(DidId),
}

#[derive(Debug, thiserror::Error)]
pub enum BusinessLogicError {
    #[error("Organisation already exists")]
    OrganisationAlreadyExists,

    #[error("Incompatible DID type, reason: {reason}")]
    IncompatibleDidType { reason: String },

    #[error("DID {0} is deactivated")]
    DidIsDeactivated(DidId),

    #[error("Invalid DID method: {method}")]
    InvalidDidMethod { method: String },

    #[error("Did value already exists: {0}")]
    DidValueAlreadyExists(DidValue),

    #[error("Credential schema already exists")]
    CredentialSchemaAlreadyExists,

    #[error("Invalid Credential state: {state}")]
    InvalidCredentialState { state: CredentialStateEnum },

    #[error("Proof schema already exists")]
    ProofSchemaAlreadyExists,

    #[error("Invalid Proof state: {state}")]
    InvalidProofState { state: ProofStateEnum },

    #[error(transparent)]
    DidDeactivation(#[from] DidDeactivationError),
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Invalid exchange type {value}: {source}")]
    InvalidExchangeType {
        value: String,
        source: anyhow::Error,
    },
    #[error("Unsupported key type: {key_type}")]
    UnsupportedKeyType { key_type: String },

    #[error("DID: Missing key")]
    DidMissingKey,

    #[error("Credential schema: Missing claims")]
    CredentialSchemaMissingClaims,

    #[error("Credential: Missing claim, schema-id: {claim_schema_id}")]
    CredentialMissingClaim { claim_schema_id: ClaimSchemaId },

    #[error("Proof schema: Missing claims")]
    ProofSchemaMissingClaims,
    #[error("Proof schema: No required claim")]
    ProofSchemaNoRequiredClaim,
    #[error("Proof schema: Duplicit claim schema")]
    ProofSchemaDuplicitClaim,
}

#[derive(Debug)]
pub enum ErrorCode {
    OrganisationAlreadyExists,

    DidNotFound,
    DidInvalidType,
    DidInvalidMethod,
    DidDeactivated,
    DidValueAlreadyExists,
    DidCannotDeactivate,
    DidMissingKey,

    CredentialSchemaAlreadyExists,
    CredentialSchemaMissingClaims,

    Credential001,
    CredentialInvalidState,
    CredentialMissingClaim,

    ProofSchemaAlreadyExists,
    ProofSchemaMissingClaims,
    ProofSchemaNoRequiredClaim,
    ProofSchemaDuplicitClaim,

    ProofInvalidState,

    InvalidExchangeType,
    UnsupportedKeyType,

    Database,
    ResponseMapping,

    Unmapped,
}

impl From<FormatError> for ServiceError {
    fn from(value: FormatError) -> Self {
        match value {
            FormatError::MappingError(value) => ServiceError::MappingError(value),
        }
    }
}

impl From<uuid::Error> for ServiceError {
    fn from(value: uuid::Error) -> Self {
        ServiceError::MappingError(value.to_string())
    }
}

impl ErrorCode {
    pub const fn msg(&self) -> &'static str {
        match self {
            ErrorCode::OrganisationAlreadyExists => "Organisation already exists",

            ErrorCode::DidNotFound => "DID not found",
            ErrorCode::DidInvalidType => "Invalid DID type",
            ErrorCode::DidInvalidMethod => "Invalid DID method",
            ErrorCode::DidDeactivated => "DID deactivated",
            ErrorCode::DidValueAlreadyExists => "DID value already exists",
            ErrorCode::DidCannotDeactivate => "DID cannot be deactivated",
            ErrorCode::DidMissingKey => "DID missing key",

            ErrorCode::CredentialSchemaAlreadyExists => "Credential schema already exists",
            ErrorCode::CredentialSchemaMissingClaims => "Credential schema: Missing claims",

            ErrorCode::Credential001 => "Credential not found",
            ErrorCode::CredentialInvalidState => "Credential state invalid",
            ErrorCode::CredentialMissingClaim => "Credential: Missing claim",

            ErrorCode::ProofSchemaAlreadyExists => "Proof schema already exists",
            ErrorCode::ProofSchemaMissingClaims => "Proof schema: Missing claims",
            ErrorCode::ProofSchemaNoRequiredClaim => "Proof schema: No required claim",
            ErrorCode::ProofSchemaDuplicitClaim => "Proof schema: Duplicit claim schema",

            ErrorCode::ProofInvalidState => "Proof state invalid",

            ErrorCode::InvalidExchangeType => "Invalid exchange type",
            ErrorCode::UnsupportedKeyType => "Unsupported key type",

            ErrorCode::Database => "Database error",

            ErrorCode::ResponseMapping => "Response mapping error",

            ErrorCode::Unmapped => "Unmapped error code",
        }
    }
}

impl ServiceError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            ServiceError::EntityNotFound(error) => error.error_code(),
            ServiceError::BusinessLogic(error) => error.error_code(),
            ServiceError::Validation(error) => error.error_code(),
            ServiceError::ResponseMapping(_) => ErrorCode::ResponseMapping,
            ServiceError::Repository(error) => error.error_code(),

            ServiceError::GeneralRuntimeError(_)
            | ServiceError::MappingError(_)
            | ServiceError::OpenID4VCError(_)
            | ServiceError::NotFound
            | ServiceError::NotUpdated
            | ServiceError::ValidationError(_)
            | ServiceError::ConfigValidationError(_)
            | ServiceError::TransportProtocolError(_)
            | ServiceError::FormatterError(_)
            | ServiceError::BitstringError(_)
            | ServiceError::MissingSigner(_)
            | ServiceError::MissingAlgorithm(_)
            | ServiceError::MissingTransportProtocol(_)
            | ServiceError::KeyAlgorithmError(_)
            | ServiceError::DidMethodError(_)
            | ServiceError::CryptoError(_)
            | ServiceError::Other(_) => ErrorCode::Unmapped,
        }
    }
}

impl EntityNotFoundError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            EntityNotFoundError::Credential(_) => ErrorCode::Credential001,
            EntityNotFoundError::Did(_) => ErrorCode::DidNotFound,
        }
    }
}

impl BusinessLogicError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            BusinessLogicError::OrganisationAlreadyExists => ErrorCode::OrganisationAlreadyExists,
            BusinessLogicError::IncompatibleDidType { .. } => ErrorCode::DidInvalidType,
            BusinessLogicError::InvalidDidMethod { .. } => ErrorCode::DidInvalidMethod,
            BusinessLogicError::DidIsDeactivated(_) => ErrorCode::DidDeactivated,
            BusinessLogicError::DidValueAlreadyExists(_) => ErrorCode::DidValueAlreadyExists,
            BusinessLogicError::CredentialSchemaAlreadyExists => {
                ErrorCode::CredentialSchemaAlreadyExists
            }
            BusinessLogicError::InvalidCredentialState { .. } => ErrorCode::CredentialInvalidState,
            BusinessLogicError::ProofSchemaAlreadyExists => ErrorCode::ProofSchemaAlreadyExists,
            BusinessLogicError::InvalidProofState { .. } => ErrorCode::ProofInvalidState,
            BusinessLogicError::DidDeactivation(error) => error.error_code(),
        }
    }
}

impl ValidationError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            ValidationError::InvalidExchangeType { .. } => ErrorCode::InvalidExchangeType,
            ValidationError::UnsupportedKeyType { .. } => ErrorCode::UnsupportedKeyType,
            ValidationError::DidMissingKey => ErrorCode::DidMissingKey,
            ValidationError::CredentialSchemaMissingClaims => {
                ErrorCode::CredentialSchemaMissingClaims
            }
            ValidationError::CredentialMissingClaim { .. } => ErrorCode::CredentialMissingClaim,
            ValidationError::ProofSchemaMissingClaims => ErrorCode::ProofSchemaMissingClaims,
            ValidationError::ProofSchemaNoRequiredClaim => ErrorCode::ProofSchemaNoRequiredClaim,
            ValidationError::ProofSchemaDuplicitClaim => ErrorCode::ProofSchemaDuplicitClaim,
        }
    }
}

// Remove this once we map all NotFound and NotUpdated errors
impl From<DataLayerError> for ServiceError {
    fn from(value: DataLayerError) -> Self {
        match value {
            DataLayerError::RecordNotFound => ServiceError::NotFound,
            DataLayerError::RecordNotUpdated => ServiceError::NotUpdated,
            _ => Self::Repository(value),
        }
    }
}
