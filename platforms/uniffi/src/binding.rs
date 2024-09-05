use std::future::Future;
use std::pin::Pin;

use tokio::fs;
use tokio::runtime::Runtime;
use tokio::sync::{RwLock, RwLockReadGuard};

use crate::error::BindingError;

type CoreBuilder = Box<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<one_core::OneCore, BindingError>>>>
        + Send
        + Sync,
>;

pub(crate) struct OneCoreBinding {
    runtime: Runtime,
    inner: RwLock<Option<one_core::OneCore>>,
    pub(crate) main_db_path: String,
    pub(crate) backup_db_path: String,
    core_builder: CoreBuilder,
}

impl OneCoreBinding {
    pub(crate) fn new(
        runtime: Runtime,
        main_db_path: String,
        backup_db_path: String,
        core_builder: CoreBuilder,
    ) -> Self {
        Self {
            runtime,
            inner: RwLock::new(None),
            main_db_path,
            backup_db_path,
            core_builder,
        }
    }

    pub fn initialize(&self, db_path: String) -> Result<(), BindingError> {
        self.runtime.block_on(async {
            let mut guard = self.inner.write().await;
            let new_core = (self.core_builder)(db_path).await?;
            guard.replace(new_core);
            Ok(())
        })
    }

    pub fn uninitialize(&self, delete_data: bool) -> Result<(), BindingError> {
        self.block_on(async {
            let mut guard = self.inner.write().await;
            if guard.take().is_none() {
                return Err(BindingError::Uninitialized);
            }

            if !delete_data {
                return Ok(());
            }

            let _ = fs::remove_file(&self.backup_db_path).await;
            fs::remove_file(&self.main_db_path).await?;

            Ok(())
        })
    }

    /// helper function to get shared access to the initialized core
    /// fails if not initialized
    pub(crate) async fn use_core(
        &self,
    ) -> Result<RwLockReadGuard<'_, one_core::OneCore>, BindingError> {
        let guard = self.inner.read().await;
        RwLockReadGuard::try_map(guard, |core| core.as_ref())
            .map_err(|_| BindingError::Uninitialized)
    }

    pub(crate) fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }
}
