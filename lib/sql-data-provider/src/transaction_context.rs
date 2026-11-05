use std::cell::RefCell;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures::FutureExt;
use migration::supported_db_type::{SupportedDbType, WithSupportedDbType};
use one_core::proto::transaction_manager::{AccessMode, IsolationLevel, TransactionManager};
use one_core::repository::error::DataLayerError;
use sea_orm::{
    ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, ExecResult, QueryResult, Statement,
    TransactionTrait,
};

use crate::DbConn;
use crate::mapper::{map_access_mode, map_isolation_level};

#[cfg(test)]
mod test;

tokio::task_local! {
    static TX_CONTEXT: (Arc<DatabaseTransaction>, Option<sea_orm::IsolationLevel>, Option<sea_orm::AccessMode>);
    static COMMIT_CALLBACKS: RefCell<Vec<Box<dyn FnOnce() + Send>>>;
}

/// Isolation level for transactions that do not request one. READ COMMITTED avoids InnoDB gap
/// locks, which cause deadlocks during parallel inserts. It is set as session default on every
/// connection (see `db_conn`) instead of per transaction: on MySQL, `SET TRANSACTION` fails if
/// the connection unexpectedly still has an open transaction, and it costs a round trip.
pub(crate) const DEFAULT_ISOLATION_LEVEL: sea_orm::IsolationLevel =
    sea_orm::IsolationLevel::ReadCommitted;

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
}

impl WithSupportedDbType for TransactionManagerImpl {
    fn supported_db_type(&self) -> SupportedDbType {
        #[expect(clippy::expect_used)]
        self.get_database_backend()
            .try_into()
            .expect("Unsupported DB type")
    }
}

#[async_trait::async_trait]
impl ConnectionTrait for TransactionManagerImpl {
    fn get_database_backend(&self) -> DbBackend {
        self.db.get_database_backend()
    }

    async fn execute_raw(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        if let Ok(tx) = TX_CONTEXT.try_with(|(v, _, _)| v.clone()) {
            tx.execute_raw(stmt).await
        } else {
            self.db.execute_raw(stmt).await
        }
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        if let Ok(tx) = TX_CONTEXT.try_with(|(v, _, _)| v.clone()) {
            tx.execute_unprepared(sql).await
        } else {
            self.db.execute_unprepared(sql).await
        }
    }

    async fn query_one_raw(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        if let Ok(tx) = TX_CONTEXT.try_with(|(v, _, _)| v.clone()) {
            tx.query_one_raw(stmt).await
        } else {
            self.db.query_one_raw(stmt).await
        }
    }

    async fn query_all_raw(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        if let Ok(tx) = TX_CONTEXT.try_with(|(v, _, _)| v.clone()) {
            tx.query_all_raw(stmt).await
        } else {
            self.db.query_all_raw(stmt).await
        }
    }
}

#[async_trait]
impl TransactionManager for TransactionManagerImpl {
    fn on_commit(&self, callback: Box<dyn FnOnce() + Send>) {
        let mut callback = Some(callback);
        if COMMIT_CALLBACKS
            .try_with(|callbacks| {
                callbacks.borrow_mut().extend(callback.take());
            })
            .is_err()
            && let Some(callback) = callback
        {
            callback();
        }
    }

    async fn transaction_with_config(
        &self,
        future: Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'async_trait>>,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<Result<(), anyhow::Error>, DataLayerError> {
        // SQLite does not support isolation levels, ignore them
        let supports_isolation = self.get_database_backend() != DbBackend::Sqlite;
        let explicit_isolation = isolation_level
            .filter(|_| supports_isolation)
            .map(map_isolation_level);
        let mut requested_isolation = explicit_isolation;
        let mut access_mode = access_mode.map(map_access_mode);
        // Check if we are already in a transaction. If we are, we need to nest deeper on the existing one.
        let new_tx = if let Ok((tx, parent_isolation, parent_access_mode)) =
            TX_CONTEXT.try_with(|v| v.clone())
        {
            tracing::trace!(
                "Nested transaction, isolation_level:{requested_isolation:?}, access_mode:{access_mode:?}"
            );

            match (parent_isolation, requested_isolation) {
                (Some(parent_isolation), Some(requested_isolation))
                    if requested_isolation == parent_isolation =>
                {
                    // allow nesting transactions with the same isolation level
                }
                (_, Some(requested_isolation)) => {
                    return Err(DataLayerError::TransactionError(format!(
                        "Nesting transactions with different isolation level: {requested_isolation:?}, parent isolation: {parent_isolation:?}"
                    )));
                }
                (_, None) => {
                    requested_isolation = parent_isolation;
                }
            };

            // A nested transaction is a SAVEPOINT and runs in the access mode of the outermost
            // transaction. Passing one would make MySQL issue `SET TRANSACTION` inside the open
            // transaction, which fails with error 1568.
            // A nested begin must not be cancelled on its own, see `TransactionManager` and
            // https://github.com/transact-rs/sqlx/issues/4445.
            access_mode = parent_access_mode;

            tx.begin_with_config(None, None).await
        } else {
            if supports_isolation && requested_isolation.is_none() {
                // Connections are opened with DEFAULT_ISOLATION_LEVEL as session default (see
                // `db_conn`), so it is not sent per transaction. It is recorded so nested
                // transactions explicitly requesting it are accepted.
                requested_isolation = Some(DEFAULT_ISOLATION_LEVEL);
            }
            tracing::trace!(
                "Non-nested transaction, isolation_level:{requested_isolation:?}, access_mode:{access_mode:?}"
            );
            // sqlx only records a transaction as started after the server acknowledged BEGIN.
            // If this future were cancelled while BEGIN is in flight, the connection would go back
            // to the pool with an open server-side transaction that is never rolled back. Running
            // BEGIN in a separate task lets it complete; a transaction whose caller is gone is
            // then rolled back when dropped.
            // Upstream: https://github.com/transact-rs/sqlx/issues/4467, fixed for MySQL by
            // https://github.com/transact-rs/sqlx/pull/4468 and for Postgres by
            // https://github.com/transact-rs/sqlx/pull/4394. The spawn can be
            // removed once a sqlx release containing both is used.
            let db = self.db.clone();
            tokio::spawn(async move { db.begin_with_config(explicit_isolation, access_mode).await })
                .await
                .map_err(|e| {
                    DataLayerError::TransactionError(format!("Failed to start transaction: {e}"))
                })?
        };
        let transaction = new_tx.map_err(|e| {
            DataLayerError::TransactionError(format!("Failed to start transaction: {e}"))
        })?;

        let fut = TX_CONTEXT.scope(
            (Arc::new(transaction), requested_isolation, access_mode),
            COMMIT_CALLBACKS.scope(RefCell::default(), async move {
                let result = future.await;
                let callbacks = COMMIT_CALLBACKS.with(RefCell::take);
                (result, callbacks)
            }),
        );
        let mut pinned = Box::pin(fut);
        let (res, callbacks) = pinned.as_mut().await;

        let value = pinned
            .as_mut()
            .take_value()
            .ok_or(DataLayerError::TransactionError(
                "No transaction available".to_string(),
            ))?;

        let tx = Arc::into_inner(value.0).ok_or(DataLayerError::TransactionError(
            "Cannot commit transaction: multiple references exist".to_string(),
        ))?;

        match &res {
            Ok(_) => {
                tx.commit().await.map_err(|e| {
                    DataLayerError::TransactionError(format!("Failed to commit transaction: {e}"))
                })?;
                // A nested commit only releases a savepoint. Keep its callbacks
                // in the parent until the outermost transaction commits.
                for callback in callbacks {
                    self.on_commit(callback);
                }
            }
            Err(inner) => {
                tx.rollback().await.map_err(|e| {
                    DataLayerError::TransactionError(format!(
                        "Failed to roll back transaction: {e}, transaction failed with: {inner}"
                    ))
                })?;
            }
        }
        Ok(res)
    }
}
