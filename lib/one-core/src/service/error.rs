use thiserror::Error;

use crate::{
    bitstring::BitstringError, config::validator::ConfigValidationError,
    provider::credential_formatter::error::FormatterError,
    provider::transport_protocol::TransportProtocolError, repository::error::DataLayerError,
};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("General repository error `{0}`")]
    GeneralRuntimeError(String),
    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error("Already exists")]
    AlreadyExists,
    #[error("Wrong parameters")]
    IncorrectParameters,
    #[error("Not found")]
    NotFound,
    #[error("Not updated")]
    NotUpdated,
    #[error("Validation errror: `{0}`")]
    ValidationError(String),
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
    #[error("Other Repository error: `{0}`")]
    Other(String),
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
