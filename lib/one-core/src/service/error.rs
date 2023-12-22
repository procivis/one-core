use shared_types::DidId;
use thiserror::Error;

use crate::config::ConfigValidationError;
use crate::crypto::error::CryptoProviderError;
use crate::model::credential::CredentialId;
use crate::model::proof::ProofId;
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
    #[error("Already shared")]
    AlreadyShared,
    #[error("Wrong parameters")]
    IncorrectParameters,
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
    #[error("Missing key")]
    MissingKey,
    #[error("Key algorithm error `{0}`")]
    KeyAlgorithmError(String),
    #[error("Did method error `{0}`")]
    DidMethodError(#[from] DidMethodError),
    #[error("Crypto provider error: `{0}`")]
    CryptoError(#[from] CryptoProviderError),
    #[error("Other Repository error: `{0}`")]
    Other(String),
    #[error(transparent)]
    DidDeactivation(#[from] DidDeactivationError),

    #[error(transparent)]
    EntityNotFound(#[from] EntityNotFoundError),
    #[error("Not found")]
    NotFound,

    #[error(transparent)]
    EntityAlreadyExists(#[from] EntityAlreadyExistsError),
    #[error("Already exists")]
    AlreadyExists,

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
pub enum EntityAlreadyExistsError {
    #[error("Proof `{0}` already exists")]
    Proof(ProofId),
    #[error("Credential `{0}` already exists")]
    Credential(CredentialId),
    #[error("DID `{0}` already exists")]
    Did(DidId),
}

#[derive(Debug, thiserror::Error)]
pub enum BusinessLogicError {
    #[error("Incompatible DID type, reason: {reason}")]
    IncompatibleDidType { reason: String },

    #[error("DID {0} is deactivated")]
    DidIsDeactivated(DidId),
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Invalid exchange type {value}: {source}")]
    InvalidExchangeType {
        value: String,
        source: anyhow::Error,
    },
}

#[derive(Debug)]
pub enum ErrorCode {
    Credential001,
    Credential002,

    Did001,
    Did002,
    Did003,

    Proof001,

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
            ErrorCode::Credential001 => "Credential not found",
            ErrorCode::Credential002 => "Credential already exits",

            ErrorCode::Did001 => "DID not found",
            ErrorCode::Did002 => "Invalid DID type",
            ErrorCode::Did003 => "DID already exits",

            ErrorCode::Proof001 => "Proof already exits",

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
            ServiceError::EntityAlreadyExists(error) => error.error_code(),

            ServiceError::GeneralRuntimeError(_)
            | ServiceError::MappingError(_)
            | ServiceError::AlreadyExists
            | ServiceError::OpenID4VCError(_)
            | ServiceError::AlreadyShared
            | ServiceError::IncorrectParameters
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
            | ServiceError::MissingKey
            | ServiceError::KeyAlgorithmError(_)
            | ServiceError::DidMethodError(_)
            | ServiceError::CryptoError(_)
            | ServiceError::Other(_)
            | ServiceError::DidDeactivation(_) => ErrorCode::Unmapped,
        }
    }
}

impl EntityNotFoundError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            EntityNotFoundError::Credential(_) => ErrorCode::Credential001,
            EntityNotFoundError::Did(_) => ErrorCode::Did001,
        }
    }
}

impl BusinessLogicError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            BusinessLogicError::IncompatibleDidType { .. } => ErrorCode::Did002,
            BusinessLogicError::DidIsDeactivated(_) => ErrorCode::Did001,
        }
    }
}

impl ValidationError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            ValidationError::InvalidExchangeType { .. } => ErrorCode::ResponseMapping,
        }
    }
}

impl EntityAlreadyExistsError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            EntityAlreadyExistsError::Credential(_) => ErrorCode::Credential002,
            EntityAlreadyExistsError::Did(_) => ErrorCode::Did003,
            EntityAlreadyExistsError::Proof(_) => ErrorCode::Proof001,
        }
    }
}

// Remove this once we map all NotFound and NotUpdated errors
impl From<DataLayerError> for ServiceError {
    fn from(value: DataLayerError) -> Self {
        match value {
            DataLayerError::AlreadyExists => ServiceError::AlreadyExists,
            DataLayerError::IncorrectParameters => ServiceError::IncorrectParameters,
            DataLayerError::RecordNotFound => ServiceError::NotFound,
            DataLayerError::RecordNotUpdated => ServiceError::NotUpdated,
            DataLayerError::Db(_) | DataLayerError::MappingError => Self::Repository(value),
        }
    }
}
