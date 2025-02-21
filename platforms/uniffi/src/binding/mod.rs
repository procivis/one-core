use std::future::Future;
use std::pin::Pin;

use one_core::service::error::ServiceError;
use tokio::fs;
use tokio::sync::{RwLock, RwLockReadGuard};
use tracing::warn;

use crate::error::{BindingError, SDKError};

pub mod backup;
pub mod ble;
pub mod cache;
mod common;
pub mod config;
pub mod credential;
pub mod credential_schema;
pub mod did;
pub mod history;
pub mod interaction;
pub mod jsonld;
pub mod key;
pub mod key_storage;
mod mapper;
pub mod organisation;
pub mod proof;
pub mod proof_schema;
pub mod revocation;
pub mod task;
pub mod trust_anchor;
pub mod trust_entity;
pub mod version;

type CoreBuilder = Box<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<one_core::OneCore, BindingError>> + Send>>
        + Send
        + Sync,
>;

#[derive(uniffi::Object)]
pub(crate) struct OneCoreBinding {
    inner: RwLock<Option<one_core::OneCore>>,
    pub(crate) main_db_path: String,
    pub(crate) backup_db_path: String,
    core_builder: CoreBuilder,
}

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn uninitialize(&self, delete_data: bool) -> Result<(), BindingError> {
        let mut guard = self.inner.write().await;
        if guard.take().is_none() {
            return Err(SDKError::NotInitialized.into());
        }

        if !delete_data {
            return Ok(());
        }

        let result = fs::remove_file(&self.backup_db_path).await;
        if let Err(err) = result {
            warn!("failed to remove backup database: {}", err);
        }
        fs::remove_file(&self.main_db_path)
            .await
            .map_err(|err| ServiceError::Other(err.to_string()))?;

        Ok(())
    }
}

impl OneCoreBinding {
    pub(crate) fn new(
        main_db_path: String,
        backup_db_path: String,
        core_builder: CoreBuilder,
    ) -> Self {
        Self {
            inner: RwLock::new(None),
            main_db_path,
            backup_db_path,
            core_builder,
        }
    }

    pub(crate) async fn initialize(&self, db_path: String) -> Result<(), BindingError> {
        let mut guard = self.inner.write().await;
        let new_core = (self.core_builder)(db_path).await?;
        guard.replace(new_core);
        Ok(())
    }

    /// helper function to get shared access to the initialized core
    /// fails if not initialized
    pub(crate) async fn use_core(
        &self,
    ) -> Result<RwLockReadGuard<'_, one_core::OneCore>, BindingError> {
        let guard = self.inner.read().await;
        RwLockReadGuard::try_map(guard, |core| core.as_ref())
            .map_err(|_| SDKError::NotInitialized.into())
    }
}
