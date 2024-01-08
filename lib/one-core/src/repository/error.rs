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
    #[error("Missing required relation {relation} for {id}")]
    MissingRequiredRelation { relation: &'static str, id: String },
}

impl DataLayerError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            DataLayerError::Db(_) => ErrorCode::Database,
            DataLayerError::AlreadyExists
            | DataLayerError::IncorrectParameters
            | DataLayerError::RecordNotFound
            | DataLayerError::RecordNotUpdated
            | DataLayerError::MappingError
            | DataLayerError::MissingRequiredRelation { .. } => ErrorCode::Unmapped,
        }
    }
}

impl From<uuid::Error> for DataLayerError {
    fn from(_: uuid::Error) -> Self {
        Self::MappingError
    }
}
