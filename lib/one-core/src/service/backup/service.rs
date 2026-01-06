use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::Context;
use futures::{FutureExt, TryFutureExt};
use one_crypto::encryption::{decrypt_file, encrypt_file};
use secrecy::SecretString;
use tempfile::{NamedTempFile, tempfile_in};

use super::BackupService;
use super::dto::{BackupCreateResponseDTO, MetadataDTO, UnexportableEntitiesResponseDTO};
use super::utils::{
    build_metadata_file_content, create_backup_history_event, create_zip, dir_path_from_file_path,
    get_metadata_from_zip, hash_reader, load_db_from_zip, map_error,
};
use crate::model::history::HistoryAction;
use crate::model::organisation::OrganisationListQuery;
use crate::repository::error::DataLayerError;
use crate::service::backup::mapper::unexportable_entities_to_response_dto;
use crate::service::error::ServiceError;

impl BackupService {
    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    pub async fn create_backup(
        &self,
        password: SecretString,
        output_path: String,
    ) -> Result<BackupCreateResponseDTO, ServiceError> {
        let output_dir = dir_path_from_file_path(&output_path)?;

        let mut db_copy = NamedTempFile::new_in(&output_dir)
            .context("Failed to create db temp file")
            .map_err(map_error)?;

        let db_metadata = self.backup_repository.copy_db_to(db_copy.path()).await?;
        let unexportable: UnexportableEntitiesResponseDTO = unexportable_entities_to_response_dto(
            self.backup_repository
                .fetch_unexportable(Some(db_copy.path()))
                .await?,
            &self.config,
        )?;
        self.backup_repository
            .delete_unexportable(db_copy.path())
            .await?;

        let organisation = self
            .organisation_repository
            .get_organisation_list(OrganisationListQuery::default())
            .await
            .and_then(|organisations| {
                organisations
                    .values
                    .into_iter()
                    .next()
                    .ok_or(DataLayerError::MappingError)
            })?;

        let history_event = create_backup_history_event(
            organisation.id,
            filename(&db_copy),
            HistoryAction::Created,
            Some(unexportable.clone().into()),
        );

        self.backup_repository
            .add_history_event(db_copy.path(), history_event.clone())
            .await?;

        let metadata_file = build_metadata_file_content(&mut db_copy, db_metadata.version)?;

        let zip_file = tempfile_in(&output_dir)
            .context("Failed to create zip temp file")
            .map_err(map_error)?;
        let zip_file = create_zip(db_copy, metadata_file, zip_file)?;
        encrypt_file(&password, &output_path, zip_file)
            .context("Failed to encrypt db file")
            .map_err(map_error)?;

        let history_id = self
            .history_repository
            .create_history(history_event)
            .await?;

        tracing::info!("Created backup `{}`", output_path);

        Ok(BackupCreateResponseDTO {
            history_id,
            file: output_path,
            unexportable,
        })
    }

    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    pub fn unpack_backup(
        password: SecretString,
        input_path: PathBuf,
        output_path: PathBuf,
    ) -> Result<MetadataDTO, ServiceError> {
        let output_dir = dir_path_from_file_path(&output_path)?;

        let zip = File::open(input_path)
            .context("Failed to open backup")
            .map_err(map_error)?;

        let mut decrypted_zip = tempfile_in(&output_dir)
            .context("Failed to create zip temp file")
            .map_err(map_error)?;

        decrypt_file(&password, zip, &mut decrypted_zip)
            .context("Failed to decrypt db file")
            .map_err(map_error)?;

        let metadata = get_metadata_from_zip(&mut decrypted_zip)?;

        let mut decrypted_db = tempfile_in(&output_dir)
            .context("Failed to create db temp file")
            .map_err(map_error)?;
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

    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn finalize_import(
        &self,
        backup_db_path: impl AsRef<Path>,
    ) -> Result<(), ServiceError> {
        self.organisation_repository
            .get_organisation_list(OrganisationListQuery::default())
            .map(|result| {
                result.and_then(|organisations| {
                    organisations
                        .values
                        .into_iter()
                        .next()
                        .ok_or(DataLayerError::MappingError)
                })
            })
            .and_then(|organisation| {
                self.history_repository
                    .create_history(create_backup_history_event(
                        organisation.id,
                        filename(backup_db_path),
                        HistoryAction::Restored,
                        None,
                    ))
            })
            .await
            .map_err(|err| {
                ServiceError::Other(format!("failed to finalize backup import: {err}"))
            })?;
        tracing::info!("Restored backup");
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    pub async fn backup_info(&self) -> Result<UnexportableEntitiesResponseDTO, ServiceError> {
        unexportable_entities_to_response_dto(
            self.backup_repository.fetch_unexportable(None).await?,
            &self.config,
        )
    }
}

fn filename(p: impl AsRef<Path>) -> String {
    p.as_ref()
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}
