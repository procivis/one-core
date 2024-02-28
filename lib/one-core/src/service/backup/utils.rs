use std::io::{self, Cursor, Read, Seek, Write};

use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::MetadataFile;
use crate::{
    crypto::hasher::sha256::SHA256,
    model::{
        history::{History, HistoryAction, HistoryEntityType},
        organisation::Organisation,
    },
    service::error::ServiceError,
};

pub(super) fn build_metadata_file_content(
    db_file: &mut impl Read,
    db_version: String,
) -> Result<MetadataFile, ServiceError> {
    let db_hash = SHA256::hash_reader(db_file)
        .map_err(|err| ServiceError::Other(format!("Failed to generate sha-256: {err}")))?;

    Ok(MetadataFile {
        db_version,
        db_hash: hex::encode(db_hash),
        created_at: OffsetDateTime::now_utc(),
    })
}

fn add_to_zip<T: Write + Seek>(
    name: &str,
    content: &mut impl Read,
    archive: &mut zip::ZipWriter<T>,
) -> Result<(), ServiceError> {
    archive
        .start_file(name, Default::default())
        .map_err(|err| ServiceError::Other(format!("Failed to create {name} in zip: {err}")))?;

    io::copy(content, archive)
        .map_err(|err| ServiceError::Other(format!("Failed to write {name} to zip: {err}")))?;

    Ok(())
}

pub(super) fn create_zip<T: Write + Seek>(
    mut db_file: impl Read,
    metadata: MetadataFile,
    zip_file: T,
) -> Result<T, ServiceError> {
    let mut archive = zip::ZipWriter::new(zip_file);

    add_to_zip("database.sqlite3", &mut db_file, &mut archive)?;
    add_to_zip(
        "metadata.json",
        &mut Cursor::new(serde_json::to_vec(&metadata).unwrap()),
        &mut archive,
    )?;

    archive
        .finish()
        .map_err(|err| ServiceError::Other(format!("Failed to finish zipping: {err}")))
}

pub(super) fn create_backup_history_event(organisation: Organisation) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Created,
        entity_id: None,
        entity_type: HistoryEntityType::Backup,
        organisation: Some(organisation),
    }
}
