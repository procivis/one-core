use std::{fs::File, sync::Arc};

use crate::{
    crypto::encryption::{decrypt_file, encrypt_file},
    model::history::HistoryAction,
    repository::{
        backup_repository::BackupRepository, error::DataLayerError,
        history_repository::HistoryRepository, organisation_repository::OrganisationRepository,
    },
    service::error::ServiceError,
};
use anyhow::Context;
use futures::{FutureExt, TryFutureExt};
use tempfile::{tempfile, NamedTempFile};

use super::{
    dto::{BackupCreateResponseDTO, MetadataDTO, UnexportableEntitiesResponseDTO},
    utils::{
        build_metadata_file_content, create_backup_history_event, create_zip,
        get_metadata_from_zip, hash_reader, load_db_from_zip, map_error,
    },
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
            .context("Failed to create db temp file")
            .map_err(map_error)?;

        let zip_file = tempfile()
            .context("Failed to create zip temp file")
            .map_err(map_error)?;

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
            .context("Failed to encrypt db file")
            .map_err(map_error)?;

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
                    .create_history(create_backup_history_event(
                        organisation,
                        HistoryAction::Created,
                    ))
            })
            .await;

        Ok(BackupCreateResponseDTO {
            file: output_path,
            unexportable,
        })
    }

    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    pub async fn unpack_backup(
        &self,
        password: String,
        input_path: String,
        output_path: String,
    ) -> Result<MetadataDTO, ServiceError> {
        let zip = File::open(input_path)
            .context("Failed to open backup")
            .map_err(map_error)?;

        let mut decrypted_zip = tempfile()
            .context("Failed to create zip temp file")
            .map_err(map_error)?;

        let mut decrypted_db = tempfile()
            .context("Failed to create db temp file")
            .map_err(map_error)?;

        decrypt_file(&password, zip, &mut decrypted_zip)
            .context("Failed to decrypt db file")
            .map_err(map_error)?;

        let metadata = get_metadata_from_zip(&mut decrypted_zip)?;
        load_db_from_zip(&mut decrypted_zip, &mut decrypted_db)?;

        let hash = hash_reader(&mut decrypted_db)?;

        if hash != metadata.db_hash {
            return Err(ServiceError::Other("hashes do not match".into()));
        }

        let mut output_file = File::create(output_path)
            .context("Failed to create output file")
            .map_err(map_error)?;

        std::io::copy(&mut decrypted_db, &mut output_file)
            .context("Failed to copy db to output path")
            .map_err(map_error)?;

        Ok(metadata)
    }

    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn finalize_import(&self) {
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
                    .create_history(create_backup_history_event(
                        organisation,
                        HistoryAction::Restored,
                    ))
            })
            .await;
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn backup_info(&self) -> Result<UnexportableEntitiesResponseDTO, ServiceError> {
        self.backup_repository
            .fetch_unexportable(None)
            .await?
            .try_into()
    }
}