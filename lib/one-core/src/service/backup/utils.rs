use std::ffi::OsStr;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use one_crypto::hasher::sha256::SHA256;
use shared_types::OrganisationId;
use uuid::Uuid;
use zip::write::SimpleFileOptions;

use super::dto::MetadataDTO;
use super::error::BackupServiceError;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
};

const DB_FILE: &str = "database.sqlite3";
const METADATA_FILE: &str = "metadata.json";

pub(super) fn hash_reader<T: Read + Seek>(reader: &mut T) -> Result<String, BackupServiceError> {
    let hash = SHA256::hash_reader(reader)?;
    let hash = hex::encode(hash);

    reader.seek(SeekFrom::Start(0))?;

    Ok(hash)
}

pub(super) fn build_metadata_file_content<T: Read + Seek>(
    db_file: &mut T,
    db_version: String,
) -> Result<MetadataDTO, BackupServiceError> {
    Ok(MetadataDTO {
        db_version,
        db_hash: hash_reader(db_file)?,
        created_at: crate::clock::now_utc(),
    })
}

fn add_to_zip<T: Write + Seek>(
    name: &str,
    content: &mut impl Read,
    archive: &mut zip::ZipWriter<T>,
) -> Result<(), BackupServiceError> {
    archive.start_file(name, SimpleFileOptions::default())?;
    io::copy(content, archive)?;
    Ok(())
}

pub(super) fn create_zip<T: Write + Seek>(
    mut db_file: impl Read,
    metadata: MetadataDTO,
    zip_file: T,
) -> Result<T, BackupServiceError> {
    let mut archive = zip::ZipWriter::new(zip_file);

    add_to_zip(DB_FILE, &mut db_file, &mut archive)?;
    add_to_zip(
        METADATA_FILE,
        &mut Cursor::new(serde_json::to_vec(&metadata)?),
        &mut archive,
    )?;

    let mut writer = archive.finish()?;
    writer.seek(SeekFrom::Start(0))?;

    Ok(writer)
}

pub(super) fn get_metadata_from_zip<T: Read + Seek>(
    zip_file: &mut T,
) -> Result<MetadataDTO, BackupServiceError> {
    let mut archive = zip::ZipArchive::new(zip_file)?;

    let reader = archive.by_name(METADATA_FILE)?;

    let metadata = serde_json::from_reader(reader)?;

    archive.into_inner().seek(SeekFrom::Start(0))?;

    Ok(metadata)
}

pub(super) fn load_db_from_zip<T: Read + Seek, K: Write + Seek>(
    zip_file: T,
    output_file: &mut K,
) -> Result<(), BackupServiceError> {
    let mut archive = zip::ZipArchive::new(zip_file)?;

    let mut reader = archive.by_name(DB_FILE)?;
    std::io::copy(&mut reader, output_file)?;
    output_file.seek(SeekFrom::Start(0))?;

    Ok(())
}

pub(super) fn create_backup_history_event(
    organisation_id: OrganisationId,
    name: String,
    action: HistoryAction,
    metadata: Option<HistoryMetadata>,
) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        action,
        name,
        source: HistorySource::Core,
        target: None,
        entity_id: None,
        entity_type: HistoryEntityType::Backup,
        metadata,
        organisation_id: Some(organisation_id),
        user: None,
    }
}

pub(super) fn dir_path_from_file_path<T: ?Sized + AsRef<OsStr>>(
    file_path: &T,
) -> Result<PathBuf, BackupServiceError> {
    let file_path = PathBuf::from(file_path);
    Ok(file_path
        .parent()
        .ok_or(BackupServiceError::InvalidPath(
            "Failed to find parent directory".to_string(),
        ))?
        .to_path_buf())
}
