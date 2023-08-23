use thiserror::Error;

use crate::config::validator::datatype::DatatypeValidationError;

#[derive(Debug, PartialEq, Error)]
pub enum DataLayerError {
    #[error("General Data Layer error `{0}`")]
    GeneralRuntimeError(String),
    #[error("Already exists")]
    AlreadyExists,
    #[error("Datatype validation error `{0}`")]
    DatatypeValidationError(#[from] DatatypeValidationError),
    #[error("Wrong parameters")]
    IncorrectParameters,
    #[error("Record not found")]
    RecordNotFound,
    #[error("Record not updated")]
    RecordNotUpdated,
    #[error("Response could not be mapped")]
    MappingError,
    #[error("Other Data Layer error")]
    Other,
}
