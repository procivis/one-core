use std::ffi::OsStr;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use anyhow::Context;
use time::OffsetDateTime;
use uuid::Uuid;
use zip::write::SimpleFileOptions;

use super::dto::MetadataDTO;
use crate::crypto::hasher::sha256::SHA256;
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistoryMetadata};
use crate::model::organisation::Organisation;
use crate::service::error::ServiceError;

const DB_FILE: &str = "database.sqlite3";
const METADATA_FILE: &str = "metadata.json";

pub(super) fn hash_reader<T: Read + Seek>(reader: &mut T) -> Result<String, ServiceError> {
    let hash = SHA256::hash_reader(reader)
        .map(hex::encode)
        .context("Failed to generate sha-256")
        .map_err(map_error)?;

    reader
        .seek(SeekFrom::Start(0))
        .context("Failed to seek back to beginning after hashing")
        .map_err(map_error)?;

    Ok(hash)
}

pub(super) fn build_metadata_file_content<T: Read + Seek>(
    db_file: &mut T,
    db_version: String,
) -> Result<MetadataDTO, ServiceError> {
    Ok(MetadataDTO {
        db_version,
        db_hash: hash_reader(db_file)?,
        created_at: OffsetDateTime::now_utc(),
    })
}

fn add_to_zip<T: Write + Seek>(
    name: &str,
    content: &mut impl Read,
    archive: &mut zip::ZipWriter<T>,
) -> Result<(), ServiceError> {
    archive
        .start_file(name, SimpleFileOptions::default())
        .with_context(|| format!("Failed to create {name} in zip"))
        .map_err(map_error)?;

    io::copy(content, archive)
        .with_context(|| format!("Failed to write {name} to zip"))
        .map_err(map_error)?;

    Ok(())
}

pub(super) fn create_zip<T: Write + Seek>(
    mut db_file: impl Read,
    metadata: MetadataDTO,
    zip_file: T,
) -> Result<T, ServiceError> {
    let mut archive = zip::ZipWriter::new(zip_file);

    add_to_zip(DB_FILE, &mut db_file, &mut archive)?;
    add_to_zip(
        METADATA_FILE,
        &mut Cursor::new(
            serde_json::to_vec(&metadata)
                .context("failed to serialize metadata")
                .map_err(map_error)?,
        ),
        &mut archive,
    )?;

    let mut writer = archive
        .finish()
        .context("Failed to finish zipping")
        .map_err(map_error)?;

    writer
        .seek(SeekFrom::Start(0))
        .context("Failed to seek back after zipping")
        .map_err(map_error)?;

    Ok(writer)
}

pub(super) fn get_metadata_from_zip<T: Read + Seek>(
    zip_file: &mut T,
) -> Result<MetadataDTO, ServiceError> {
    let mut archive = zip::ZipArchive::new(zip_file)
        .context("Failed to open zip")
        .map_err(map_error)?;

    let reader = archive
        .by_name(METADATA_FILE)
        .with_context(|| format!("Failed to open {METADATA_FILE} in zip"))
        .map_err(map_error)?;

    let metadata = serde_json::from_reader(reader)
        .with_context(|| format!("Failed to deserialize {METADATA_FILE} from zip"))
        .map_err(map_error)?;

    archive
        .into_inner()
        .seek(SeekFrom::Start(0))
        .context("Failed to seek back after reading from zip")
        .map_err(map_error)?;

    Ok(metadata)
}

pub(super) fn load_db_from_zip<T: Read + Seek, K: Write + Seek>(
    zip_file: T,
    output_file: &mut K,
) -> Result<(), ServiceError> {
    let mut archive = zip::ZipArchive::new(zip_file)
        .context("Failed to open zip")
        .map_err(map_error)?;

    let mut reader = archive
        .by_name(DB_FILE)
        .with_context(|| format!("Failed to open {DB_FILE} in zip"))
        .map_err(map_error)?;

    std::io::copy(&mut reader, output_file)
        .with_context(|| format!("Failed to read {DB_FILE} from zip"))
        .map_err(map_error)?;

    output_file
        .seek(SeekFrom::Start(0))
        .context("Failed to seek back after reading from zip")
        .map_err(map_error)?;

    Ok(())
}

pub(super) fn create_backup_history_event(
    organisation: Organisation,
    action: HistoryAction,
    metadata: Option<HistoryMetadata>,
) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        entity_id: None,
        entity_type: HistoryEntityType::Backup,
        metadata,
        organisation: Some(organisation),
    }
}

pub(super) fn map_error(err: anyhow::Error) -> ServiceError {
    ServiceError::Other(format!("{:?}", err))
}

pub(super) fn dir_path_from_file_path<T: ?Sized + AsRef<OsStr>>(
    file_path: &T,
) -> Result<PathBuf, ServiceError> {
    let file_path = PathBuf::from(file_path);
    Ok(file_path
        .parent()
        .ok_or(ServiceError::Other(
            "Failed to find parent directory".to_string(),
        ))?
        .to_path_buf())
}
