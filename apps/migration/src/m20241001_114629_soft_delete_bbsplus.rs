use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// We changed the way BBS+ credential proofs are encoded in ONE-3309, which is a breaking change.
// We removed the implicit JSON-LD credential subject nesting in ONE-3347, which is a breaking change.
const PLACEHOLDER_DATE: &str = "2001-01-01 00:00:00";
const AFFECTED_FORMATS: [&str; 2] = ["JSON_LD_BBSPLUS", "JSON_LD_CLASSIC"];

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
                        AND credential_schema.format IN ('{}', '{}')
                        AND credential.deleted_at IS NULL
                    );",
                    AFFECTED_FORMATS[0], AFFECTED_FORMATS[1]
                )
            }
            _ => {
                format!(
                    "UPDATE credential
                    JOIN credential_schema ON credential.credential_schema_id = credential_schema.id
                    SET credential.deleted_at = '{PLACEHOLDER_DATE}'
                    WHERE credential_schema.format in ('{}', '{}')
                    AND credential.deleted_at IS NULL;",
                    AFFECTED_FORMATS[0], AFFECTED_FORMATS[1]
                )
            }
        };

        db.execute_unprepared(&query).await?;

        Ok(())
    }
}
