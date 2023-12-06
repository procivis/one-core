use crate::{error::BindingError, utils::run_sync};
use tokio::{
    fs,
    sync::{RwLock, RwLockReadGuard},
};

pub(crate) struct OneCoreBinding {
    inner: RwLock<Option<one_core::OneCore>>,
    db_path: String,
}

impl OneCoreBinding {
    pub(crate) fn new(core: one_core::OneCore, db_path: String) -> Self {
        Self {
            inner: RwLock::new(Some(core)),
            db_path,
        }
    }

    pub fn uninitialize(&self, delete_data: bool) -> Result<(), BindingError> {
        run_sync(async {
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
}
