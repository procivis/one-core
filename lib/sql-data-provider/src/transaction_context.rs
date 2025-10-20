use std::fmt::{Debug, Display};
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use one_core::proto::transaction_manager;
use one_core::proto::transaction_manager::TransactionManager;
use one_core::repository::error::DataLayerError;
use one_core::service::error::ServiceError;
use sea_orm::{
    AccessMode, ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, ExecResult, IsolationLevel,
    QueryResult, Statement, TransactionError, TransactionTrait,
};

use crate::DbConn;
use crate::mapper::{map_access_mode, map_isolation_level};

pub trait TransactionProvider: Send + Sync {
    fn tx(&self) -> TransactionWrapper;
}

tokio::task_local! {
    static TX_CONTEXT: Arc<DatabaseTransaction>;
}

#[derive(Debug)]
pub enum TransactionWrapper {
    Managed(Arc<DatabaseTransaction>),
    AutoCommit(DbConn),
}

#[async_trait::async_trait]
impl ConnectionTrait for TransactionWrapper {
    fn get_database_backend(&self) -> DbBackend {
        match &self {
            TransactionWrapper::Managed(tx) => tx.get_database_backend(),
            TransactionWrapper::AutoCommit(conn) => conn.get_database_backend(),
        }
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        match &self {
            TransactionWrapper::Managed(tx) => tx.execute(stmt).await,
            TransactionWrapper::AutoCommit(conn) => conn.execute(stmt).await,
        }
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        match &self {
            TransactionWrapper::Managed(tx) => tx.execute_unprepared(sql).await,
            TransactionWrapper::AutoCommit(conn) => conn.execute_unprepared(sql).await,
        }
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        match &self {
            TransactionWrapper::Managed(tx) => tx.query_one(stmt).await,
            TransactionWrapper::AutoCommit(conn) => conn.query_one(stmt).await,
        }
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        match &self {
            TransactionWrapper::Managed(tx) => tx.query_all(stmt).await,
            TransactionWrapper::AutoCommit(conn) => conn.query_all(stmt).await,
        }
    }
}

#[async_trait::async_trait]
impl TransactionTrait for TransactionWrapper {
    async fn begin(&self) -> Result<DatabaseTransaction, DbErr> {
        match &self {
            TransactionWrapper::Managed(tx) => tx.begin().await,
            TransactionWrapper::AutoCommit(conn) => conn.begin().await,
        }
    }

    async fn begin_with_config(
        &self,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<DatabaseTransaction, DbErr> {
        match &self {
            TransactionWrapper::Managed(tx) => {
                tx.begin_with_config(isolation_level, access_mode).await
            }
            TransactionWrapper::AutoCommit(conn) => {
                conn.begin_with_config(isolation_level, access_mode).await
            }
        }
    }

    async fn transaction<F, T, E>(&self, callback: F) -> Result<T, TransactionError<E>>
    where
        F: for<'c> FnOnce(
                &'c DatabaseTransaction,
            ) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'c>>
            + Send,
        T: Send,
        E: Display + Debug + Send,
    {
        match &self {
            TransactionWrapper::Managed(tx) => tx.transaction(callback).await,
            TransactionWrapper::AutoCommit(conn) => conn.transaction(callback).await,
        }
    }

    async fn transaction_with_config<F, T, E>(
        &self,
        callback: F,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<T, TransactionError<E>>
    where
        F: for<'c> FnOnce(
                &'c DatabaseTransaction,
            ) -> Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'c>>
            + Send,
        T: Send,
        E: Display + Debug + Send,
    {
        match &self {
            TransactionWrapper::Managed(tx) => {
                tx.transaction_with_config(callback, isolation_level, access_mode)
                    .await
            }
            TransactionWrapper::AutoCommit(conn) => {
                conn.transaction_with_config(callback, isolation_level, access_mode)
                    .await
            }
        }
    }
}

pub struct TransactionManagerImpl {
    db: DbConn,
}

impl TransactionManagerImpl {
    pub fn new(db: DbConn) -> Self {
        Self { db }
    }
}

impl TransactionProvider for TransactionManagerImpl {
    fn tx(&self) -> TransactionWrapper {
        if let Ok(tx) = TX_CONTEXT.try_with(|v| v.clone()) {
            TransactionWrapper::Managed(tx)
        } else {
            TransactionWrapper::AutoCommit(self.db.clone())
        }
    }
}

#[async_trait]
impl TransactionManager for TransactionManagerImpl {
    async fn transaction_with_config(
        &self,
        future: Pin<Box<dyn Future<Output = Result<(), ServiceError>> + Send + 'async_trait>>,
        isolation_level: Option<transaction_manager::IsolationLevel>,
        access_mode: Option<transaction_manager::AccessMode>,
    ) -> Result<Result<(), ServiceError>, DataLayerError> {
        let isolation_level = isolation_level.map(map_isolation_level);
        let access_mode = access_mode.map(map_access_mode);
        // Check if we are already in a transaction. If we are, we need to nest deeper on the existing one.
        let new_tx = if let Ok(tx) = TX_CONTEXT.try_with(|v| v.clone()) {
            tx.begin_with_config(isolation_level, access_mode).await
        } else {
            self.db
                .begin_with_config(isolation_level, access_mode)
                .await
        };
        let transaction = new_tx.map_err(|e| {
            DataLayerError::TransactionError(format!("Failed to start transaction: {e}"))
        })?;

        let fut = TX_CONTEXT.scope(Arc::new(transaction), future);
        let mut pinned = Box::pin(fut);
        let res = pinned.as_mut().await;

        let value = pinned
            .as_mut()
            .take_value()
            .ok_or(DataLayerError::TransactionError(
                "No transaction available".to_string(),
            ))?;

        let tx = Arc::into_inner(value).ok_or(DataLayerError::TransactionError(
            "Cannot commit transaction: multiple references exist".to_string(),
        ))?;

        match &res {
            Ok(_) => {
                tx.commit().await.map_err(|e| {
                    DataLayerError::TransactionError(format!("Failed to commit transaction: {e}"))
                })?;
            }
            Err(_) => {
                tx.rollback().await.map_err(|e| {
                    DataLayerError::TransactionError(format!(
                        "Failed to roll back transaction: {e}"
                    ))
                })?;
            }
        }
        Ok(res)
    }
}
