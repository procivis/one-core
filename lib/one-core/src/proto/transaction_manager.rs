use std::pin::Pin;

use async_trait::async_trait;
use futures::FutureExt;

use crate::repository::error::DataLayerError;

#[async_trait]
pub trait TransactionManager: Send + Sync {
    async fn transaction(
        &self,
        future: Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'async_trait>>,
    ) -> Result<Result<(), anyhow::Error>, DataLayerError> {
        self.transaction_with_config(future, None, None).await
    }

    async fn transaction_with_config(
        &self,
        future: Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'async_trait>>,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<Result<(), anyhow::Error>, DataLayerError>;
}

impl<'a> dyn TransactionManager + 'a {
    pub async fn tx<T, E>(
        &self,
        future: impl Future<Output = Result<T, E>> + Send + 'a,
    ) -> Result<Result<T, E>, DataLayerError>
    where
        T: Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        self.tx_with_config(future.boxed(), None, None).await
    }

    pub async fn tx_with_config<T, E>(
        &self,
        future: impl Future<Output = Result<T, E>> + Send + 'a,
        isolation_level: Option<IsolationLevel>,
        access_mode: Option<AccessMode>,
    ) -> Result<Result<T, E>, DataLayerError>
    where
        T: Send + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        let mut result = None;
        let boxed = async {
            result = Some(future.await?);
            Ok(())
        }
        .boxed();
        let err = self
            .transaction_with_config(boxed, isolation_level, access_mode)
            .await?;
        if let Err(e) = err {
            let err = anyhow::Error::downcast::<E>(e).map_err(|e| {
                DataLayerError::TransactionError(format!("Failed to downcast error: {e}",))
            })?;
            return Ok(Err(err));
        }
        Ok(Ok(result.ok_or(DataLayerError::TransactionError(
            "Failed to unpack transaction result".to_string(),
        ))?))
    }
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
        future: Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + Send + 'async_trait>>,
        _isolation_level: Option<IsolationLevel>,
        _access_mode: Option<AccessMode>,
    ) -> Result<Result<(), anyhow::Error>, DataLayerError> {
        Ok(future.await)
    }
}
