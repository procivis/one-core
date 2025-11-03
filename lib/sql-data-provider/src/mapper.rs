use one_core::model::common::{LockType, SortDirection};
use one_core::proto::transaction_manager;
use one_core::repository::error::DataLayerError;
use one_core::service::error::ServiceError;
use sea_orm::{AccessMode, DbErr, IsolationLevel, Order, SqlErr};

pub(crate) fn order_from_sort_direction(direction: SortDirection) -> Order {
    match direction {
        SortDirection::Ascending => Order::Asc,
        SortDirection::Descending => Order::Desc,
    }
}

pub(crate) fn to_data_layer_error(e: DbErr) -> DataLayerError {
    match e.sql_err() {
        Some(SqlErr::UniqueConstraintViolation(_)) => DataLayerError::AlreadyExists,
        Some(SqlErr::ForeignKeyConstraintViolation(_)) => DataLayerError::IncorrectParameters,
        Some(_) | None => DataLayerError::Db(e.into()),
    }
}

pub(crate) fn to_update_data_layer_error(err: DbErr) -> DataLayerError {
    match err {
        DbErr::RecordNotUpdated | DbErr::RecordNotFound(_) => DataLayerError::RecordNotUpdated,
        e => to_data_layer_error(e),
    }
}

pub(crate) fn map_isolation_level(level: transaction_manager::IsolationLevel) -> IsolationLevel {
    match level {
        transaction_manager::IsolationLevel::RepeatableRead => IsolationLevel::RepeatableRead,
        transaction_manager::IsolationLevel::ReadCommitted => IsolationLevel::ReadCommitted,
        transaction_manager::IsolationLevel::ReadUncommitted => IsolationLevel::ReadUncommitted,
        transaction_manager::IsolationLevel::Serializable => IsolationLevel::Serializable,
    }
}

pub(crate) fn map_access_mode(level: transaction_manager::AccessMode) -> AccessMode {
    match level {
        transaction_manager::AccessMode::ReadOnly => AccessMode::ReadOnly,
        transaction_manager::AccessMode::ReadWrite => AccessMode::ReadWrite,
    }
}

pub(crate) fn map_lock_type(level: LockType) -> sea_orm::sea_query::LockType {
    match level {
        LockType::Update => sea_orm::sea_query::LockType::Update,
        LockType::Share => sea_orm::sea_query::LockType::Share,
    }
}

pub(crate) fn unpack_data_layer_error(e: ServiceError) -> DataLayerError {
    match e {
        ServiceError::Repository(err) => err,
        err => DataLayerError::TransactionError(format!("transaction failed: {err}")),
    }
}
