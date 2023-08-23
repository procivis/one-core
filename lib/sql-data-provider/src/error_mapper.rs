use one_core::repository::error::DataLayerError;
use sea_orm::{DbErr, SqlErr};

pub(crate) fn to_data_layer_error(e: DbErr) -> DataLayerError {
    match e.sql_err() {
        Some(sql_error) if matches!(sql_error, SqlErr::UniqueConstraintViolation(_)) => {
            DataLayerError::AlreadyExists
        }
        Some(sql_error) if matches!(sql_error, SqlErr::ForeignKeyConstraintViolation(_)) => {
            DataLayerError::IncorrectParameters
        }
        Some(_) => DataLayerError::GeneralRuntimeError(e.to_string()),
        None => DataLayerError::GeneralRuntimeError(e.to_string()),
    }
}
