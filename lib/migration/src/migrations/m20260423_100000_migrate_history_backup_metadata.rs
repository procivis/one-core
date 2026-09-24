use sea_orm_migration::prelude::*;

use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

// A number of new fields were added / modified on UnexportableEntitiesResponseDTO
// Entries written prior to these changes can not be parsed.
// This migration updates the metadata to conform to the new structure.
//
// We only update the history entry when:
// - entity_type = BACKUP
// - metadata IS NOT NULL
// - $.UnexportableEntities IS NOT NULL

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Only mobile wallets (SQLite) ever write UnexportableEntities history metadata
        if manager.supported_db_type() != SupportedDbType::Sqlite {
            return Ok(());
        }

        let db = manager.get_connection();

        // Top level identifiers field added post-v1.50.1 (Vec<Identifier> + count)
        // Populate if absent
        db.execute_unprepared(
            r#"
            UPDATE history
            SET metadata = json_insert(
                metadata,
                '$.UnexportableEntities.identifiers',       json('[]'),
                '$.UnexportableEntities.total_identifiers', 0
            )
            WHERE entity_type = 'BACKUP'
              AND metadata IS NOT NULL
              AND json_extract(metadata, '$.UnexportableEntities') IS NOT NULL
              AND (   json_extract(metadata, '$.UnexportableEntities.identifiers')       IS NULL
                   OR json_extract(metadata, '$.UnexportableEntities.total_identifiers') IS NULL);
            "#,
        )
        .await?;

        // Top level history field added post-v1.50.1 (Vec<HistoryResponse> + count)
        // Populate if absent
        db.execute_unprepared(
            r#"
            UPDATE history
            SET metadata = json_insert(
                metadata,
                '$.UnexportableEntities.history',         json('[]'),
                '$.UnexportableEntities.total_histories', 0
            )
            WHERE entity_type = 'BACKUP'
              AND metadata IS NOT NULL
              AND json_extract(metadata, '$.UnexportableEntities') IS NOT NULL
              AND (   json_extract(metadata, '$.UnexportableEntities.history')         IS NULL
                   OR json_extract(metadata, '$.UnexportableEntities.total_histories') IS NULL);
            "#,
        )
        .await?;

        // KeyListItemResponseDTO now has a required is_remote field
        // if absent, we set it to false
        db.execute_unprepared(
            r#"
            UPDATE history
            SET metadata = json_set(
                metadata,
                '$.UnexportableEntities.keys',
                (
                    SELECT COALESCE(json_group_array(
                        CASE WHEN json_extract(value, '$.is_remote') IS NULL
                             THEN json_set(value, '$.is_remote', json('false'))
                             ELSE value
                        END
                    ), json('[]'))
                    FROM json_each(json_extract(metadata, '$.UnexportableEntities.keys'))
                )
            )
            WHERE entity_type = 'BACKUP'
              AND metadata IS NOT NULL
              AND json_extract(metadata, '$.UnexportableEntities') IS NOT NULL
              AND EXISTS (
                    SELECT 1
                    FROM json_each(json_extract(metadata, '$.UnexportableEntities.keys'))
                    WHERE json_extract(value, '$.is_remote') IS NULL
              );
            "#,
        )
        .await?;

        // CredentialDetailResponseDTO changed substantially, e.g.
        // exchange renamed to protocol
        // issuer_did / holder_did
        // several new fields, etc.
        //
        // we set the array to [] if we detect the old structure
        // total_credentials is preserved
        db.execute_unprepared(
            r#"
            UPDATE history
            SET metadata = json_set(metadata, '$.UnexportableEntities.credentials', json('[]'))
            WHERE entity_type = 'BACKUP'
              AND metadata IS NOT NULL
              AND json_extract(metadata, '$.UnexportableEntities') IS NOT NULL
              AND EXISTS (
                    SELECT 1
                    FROM json_each(json_extract(metadata, '$.UnexportableEntities.credentials'))
                    WHERE json_extract(value, '$.protocol') IS NULL
              );
            "#,
        )
        .await?;

        Ok(())
    }
}
