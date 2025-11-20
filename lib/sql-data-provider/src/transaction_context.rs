use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures::FutureExt;
use one_core::proto::transaction_manager;
use one_core::proto::transaction_manager::{AccessMode, IsolationLevel, TransactionManager};
use one_core::repository::error::DataLayerError;
use sea_orm::{
    ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, ExecResult, QueryResult, Statement,
    TransactionTrait,
};

use crate::DbConn;
use crate::mapper::{map_access_mode, map_isolation_level};

tokio::task_local! {
    static TX_CONTEXT: Arc<DatabaseTransaction>;
}

#[derive(Clone)]
pub struct TransactionManagerImpl {
    db: DbConn,
}

impl TransactionManagerImpl {
    pub fn new(db: DbConn) -> Self {
        Self { db }
    }

    pub async fn tx<T, E>(
        &self,
        future: impl Future<Output = Result<T, E>> + Send,
    ) -> Result<Result<T, E>, DataLayerError>
    where
        T: Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        (self as &dyn TransactionManager).tx(future.boxed()).await
    }

    pub async fn tx_with_config<T, E>(
        &self,
        future: impl Future<Output = Result<T, E>> + Send,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<Result<T, E>, DataLayerError>
    where
        T: Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        (self as &dyn TransactionManager)
            .tx_with_config(future.boxed(), isolation_level, access_mode)
            .await
    }
}

#[async_trait::async_trait]
impl ConnectionTrait for TransactionManagerImpl {
    fn get_database_backend(&self) -> DbBackend {
        self.db.get_database_backend()
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        if let Ok(tx) = TX_CONTEXT.try_with(|v| v.clone()) {
            tx.execute(stmt).await
        } else {
            self.db.execute(stmt).await
        }
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        if let Ok(tx) = TX_CONTEXT.try_with(|v| v.clone()) {
            tx.execute_unprepared(sql).await
        } else {
            self.db.execute_unprepared(sql).await
        }
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        if let Ok(tx) = TX_CONTEXT.try_with(|v| v.clone()) {
            tx.query_one(stmt).await
        } else {
            self.db.query_one(stmt).await
        }
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        if let Ok(tx) = TX_CONTEXT.try_with(|v| v.clone()) {
            tx.query_all(stmt).await
        } else {
            self.db.query_all(stmt).await
        }
    }
}

#[async_trait]
impl TransactionManager for TransactionManagerImpl {
    async fn transaction_with_config(
        &self,
        future: Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'async_trait>>,
        isolation_level: Option<transaction_manager::IsolationLevel>,
        access_mode: Option<transaction_manager::AccessMode>,
    ) -> Result<Result<(), anyhow::Error>, DataLayerError> {
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
