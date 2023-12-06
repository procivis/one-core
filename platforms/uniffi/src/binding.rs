use std::future::Future;

use crate::error::BindingError;
use tokio::{
    fs,
    runtime::Runtime,
    sync::{RwLock, RwLockReadGuard},
};

pub(crate) struct OneCoreBinding {
    runtime: Runtime,
    inner: RwLock<Option<one_core::OneCore>>,
    db_path: String,
}

impl OneCoreBinding {
    pub(crate) fn new(core: one_core::OneCore, db_path: String, runtime: Runtime) -> Self {
        Self {
            inner: RwLock::new(Some(core)),
            db_path,
            runtime,
        }
    }

    pub fn uninitialize(&self, delete_data: bool) -> Result<(), BindingError> {
        self.runtime.block_on(async {
            let mut guard = self.inner.write().await;
            if guard.take().is_none() {
                return Err(BindingError::Uninitialized);
            }

            if delete_data {
                fs::remove_file(&self.db_path)
                    .await
                    .map_err(|e| BindingError::Unknown(e.to_string()))?;
            }
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
