use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Motivation for this migration: ONE-3022
const PLACEHOLDER_DATE: &str = "2000-01-01 00:00:00";
const AFFECTED_FORMAT: &str = "JSON_LD_CLASSIC";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        let query = match manager.get_database_backend() {
            DatabaseBackend::Sqlite => {
                format!(
                    "UPDATE credential
                    SET deleted_at = '{PLACEHOLDER_DATE}'
                    WHERE EXISTS (
                        SELECT 1
                        FROM credential_schema
                        WHERE credential.credential_schema_id = credential_schema.id
                        AND credential_schema.format = '{AFFECTED_FORMAT}'
                        AND credential.deleted_at IS NULL
                    );"
                )
            }
            _ => {
                format!(
                    "UPDATE credential
                    JOIN credential_schema ON credential.credential_schema_id = credential_schema.id
                    SET credential.deleted_at = '{PLACEHOLDER_DATE}'
                    WHERE credential_schema.format = '{AFFECTED_FORMAT}'
                    AND credential.deleted_at IS NULL;"
                )
            }
        };

        db.execute_unprepared(&query).await?;

        Ok(())
    }
}
