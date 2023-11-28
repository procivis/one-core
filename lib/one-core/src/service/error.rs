use thiserror::Error;

use super::did::DidDeactivationError;
use crate::config::ConfigValidationError;
use crate::crypto::error::CryptoProviderError;
use crate::service::oidc::dto::OpenID4VCIError;
use crate::{
    provider::credential_formatter::error::FormatterError,
    provider::did_method::DidMethodError,
    provider::transport_protocol::TransportProtocolError,
    repository::error::DataLayerError,
    util::{bitstring::BitstringError, oidc::FormatError},
};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("General repository error `{0}`")]
    GeneralRuntimeError(String),
    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error("Already exists")]
    AlreadyExists,
    #[error("Already shared")]
    AlreadyShared,
    #[error("Wrong parameters")]
    IncorrectParameters,
    #[error("Not found")]
    NotFound,
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
}

impl From<DataLayerError> for ServiceError {
    fn from(value: DataLayerError) -> Self {
        match value {
            DataLayerError::GeneralRuntimeError(e) => ServiceError::GeneralRuntimeError(e),
            DataLayerError::AlreadyExists => ServiceError::AlreadyExists,
            DataLayerError::ConfigValidationError(e) => {
                ServiceError::ValidationError(e.to_string())
            }
            DataLayerError::IncorrectParameters => ServiceError::IncorrectParameters,
            DataLayerError::MappingError => {
                ServiceError::MappingError("Internal mapping error".to_string())
            }
            DataLayerError::Other => ServiceError::Other("Other internal error".to_string()),
            DataLayerError::RecordNotFound => ServiceError::NotFound,
            DataLayerError::RecordNotUpdated => ServiceError::NotUpdated,
        }
    }
}

impl From<FormatError> for ServiceError {
    fn from(value: FormatError) -> Self {
        match value {
            FormatError::MappingError(value) => ServiceError::MappingError(value),
        }
    }
}
