use std::pin::Pin;

use async_trait::async_trait;

use crate::repository::error::DataLayerError;
use crate::service::error::ServiceError;

#[async_trait]
pub trait TransactionManager: Send + Sync {
    async fn transaction(
        &self,
        future: Pin<Box<dyn Future<Output = Result<(), ServiceError>> + Send + 'async_trait>>,
    ) -> Result<Result<(), ServiceError>, DataLayerError> {
        self.transaction_with_config(future, None, None).await
    }

    async fn transaction_with_config(
        &self,
        future: Pin<Box<dyn Future<Output = Result<(), ServiceError>> + Send + 'async_trait>>,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<Result<(), ServiceError>, DataLayerError>;
}

pub enum IsolationLevel {
    /// Consistent reads within the same transaction read the snapshot established by the first read.
    RepeatableRead,
    /// Each consistent read, even within the same transaction, sets and reads its own fresh snapshot.
    ReadCommitted,
    /// SELECT statements are performed in a nonlocking fashion, but a possible earlier version of a row might be used.
    ReadUncommitted,
    /// All statements of the current transaction can only see rows committed before the first query or data-modification statement was executed in this transaction.
    Serializable,
}

pub enum AccessMode {
    /// Data can't be modified in this transaction
    ReadOnly,
    /// Data can be modified in this transaction (default)
    ReadWrite,
}

/// Transaction manager that does _not_ provide transactions. Useful in test scenarios.
pub struct NoTransactionManager;

#[async_trait]
impl TransactionManager for NoTransactionManager {
    async fn transaction_with_config(
        &self,
        future: Pin<Box<dyn Future<Output = Result<(), ServiceError>> + Send + 'async_trait>>,
        _isolation_level: Option<IsolationLevel>,
        _access_mode: Option<AccessMode>,
    ) -> Result<Result<(), ServiceError>, DataLayerError> {
        Ok(future.await)
    }
}
