use one_core::{
    config::ConfigParseError, provider::transport_protocol::TransportProtocolError,
    service::error::ServiceError,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BindingError {
    #[error("Already exists: `{0}`")]
    AlreadyExists(String),
    #[error("Not found: `{0}`")]
    NotFound(String),
    #[error("Not supported: `{0}`")]
    NotSupported(String),
    #[error("Validation errror: `{0}`")]
    ValidationError(String),
    #[error("Config validation error `{0}`")]
    ConfigValidationError(String),
    #[error("Unknown error: `{0}`")]
    Unknown(String),
}

impl From<ServiceError> for BindingError {
    fn from(error: ServiceError) -> Self {
        match &error {
            ServiceError::AlreadyExists => Self::AlreadyExists(error.to_string()),
            ServiceError::NotFound => Self::NotFound(error.to_string()),
            ServiceError::ValidationError(_) => Self::ValidationError(error.to_string()),
            ServiceError::ConfigValidationError(_) => {
                Self::ConfigValidationError(error.to_string())
            }
            ServiceError::TransportProtocolError(e) => match e {
                TransportProtocolError::OperationNotSupported => {
                    Self::NotSupported(error.to_string())
                }
                error => Self::Unknown(error.to_string()),
            },
            error => Self::Unknown(error.to_string()),
        }
    }
}

impl From<ConfigParseError> for BindingError {
    fn from(error: ConfigParseError) -> Self {
        Self::ConfigValidationError(error.to_string())
    }
}
