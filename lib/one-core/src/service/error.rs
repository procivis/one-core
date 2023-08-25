use thiserror::Error;

use crate::{config::validator::ConfigValidationError, repository::error::DataLayerError};

#[derive(Debug, PartialEq, Error)]
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
