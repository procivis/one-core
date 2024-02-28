use std::sync::Arc;

use crate::{
    crypto::encryption::encrypt_file,
    repository::{
        backup_repository::BackupRepository, error::DataLayerError,
        history_repository::HistoryRepository, organisation_repository::OrganisationRepository,
    },
    service::error::ServiceError,
};
use futures::{FutureExt, TryFutureExt};
use tempfile::NamedTempFile;

use super::{
    dto::{BackupCreateResponseDTO, UnexportableEntitiesResponseDTO},
    utils::{build_metadata_file_content, create_backup_history_event, create_zip},
    BackupService,
};

impl BackupService {
    pub fn new(
        backup_repository: Arc<dyn BackupRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
    ) -> Self {
        Self {
            backup_repository,
            history_repository,
            organisation_repository,
        }
    }

    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    pub async fn create_backup(
        &self,
        password: String,
        output_path: String,
    ) -> Result<BackupCreateResponseDTO, ServiceError> {
        let mut db_copy = NamedTempFile::new()
            .map_err(|err| ServiceError::Other(format!("Failed to create db temp file: {err}")))?;

        let zip_file = NamedTempFile::new()
            .map_err(|err| ServiceError::Other(format!("Failed to create zip temp file: {err}")))?;

        let db_metadata = self.backup_repository.copy_db_to(db_copy.path()).await?;
        let unexportable = self
            .backup_repository
            .fetch_unexportable(Some(db_copy.path()))
            .await?
            .try_into()?;
        self.backup_repository
            .delete_unexportable(db_copy.path())
            .await?;

        let metadata_file = build_metadata_file_content(&mut db_copy, db_metadata.version)?;
        let zip_file = create_zip(db_copy, metadata_file, zip_file)?;
        encrypt_file(&password, &output_path, zip_file)
            .map_err(|err| ServiceError::Other(format!("Failed to encrypt db file: {err}")))?;

        let _ = self
            .organisation_repository
            .get_organisation_list()
            .map(|result| {
                result.and_then(|organisations| {
                    organisations
                        .into_iter()
                        .next()
                        .ok_or(DataLayerError::MappingError)
                })
            })
            .and_then(|organisation| {
                self.history_repository
                    .create_history(create_backup_history_event(organisation))
            })
            .await;

        Ok(BackupCreateResponseDTO {
            file: output_path,
            unexportable,
        })
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn backup_info(&self) -> Result<UnexportableEntitiesResponseDTO, ServiceError> {
        self.backup_repository
            .fetch_unexportable(None)
            .await?
            .try_into()
    }
}
