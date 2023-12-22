use thiserror::Error;

use crate::service::error::ErrorCode;

#[derive(Debug, Error)]
pub enum DataLayerError {
    #[error("Already exists")]
    AlreadyExists,
    #[error("Wrong parameters")]
    IncorrectParameters,
    #[error("Record not found")]
    RecordNotFound,
    #[error("Record not updated")]
    RecordNotUpdated,
    #[error("Response could not be mapped")]
    MappingError,
    #[error("Database error: {0}")]
    Db(anyhow::Error),
}

impl DataLayerError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            DataLayerError::AlreadyExists
            | DataLayerError::IncorrectParameters
            | DataLayerError::RecordNotFound
            | DataLayerError::RecordNotUpdated
            | DataLayerError::MappingError => ErrorCode::Unmapped,
            DataLayerError::Db(_) => ErrorCode::Database,
        }
    }
}

impl From<uuid::Error> for DataLayerError {
    fn from(_: uuid::Error) -> Self {
        Self::MappingError
    }
}
