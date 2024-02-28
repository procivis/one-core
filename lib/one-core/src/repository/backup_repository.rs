use std::path::Path;

use super::error::DataLayerError;
use crate::model::backup::Metadata;
use crate::model::backup::UnexportableEntities;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait BackupRepository: Send + Sync {
    async fn copy_db_to(&self, path: &Path) -> Result<Metadata, DataLayerError>;
    async fn fetch_unexportable<'a>(
        &self,
        path: Option<&'a Path>,
    ) -> Result<UnexportableEntities, DataLayerError>;
    async fn delete_unexportable(&self, path: &Path) -> Result<(), DataLayerError>;
}
