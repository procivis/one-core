use sea_orm_migration::prelude::*;

use crate::m20240319_105859_typed_credential_schema::SCHEMA_ID_IN_ORGANISATION_INDEX;

#[derive(DeriveMigrationName)]
pub struct Migration;

pub const UNIQUE_INDEX_CREDENTIAL_SCHEMA_ORGANISATION_TYPE_ID_DELETED_AT_UNIQUE: &str =
    "index-SchemaId-Organisation-SchemaType-DeletedAt_Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        match manager.get_database_backend() {
            sea_orm::DatabaseBackend::MySql => {
                let q1 = "ALTER TABLE credential_schema ADD COLUMN deleted_at_materialized VARCHAR(50) AS (COALESCE(deleted_at, 'not_deleted')) PERSISTENT;".to_string();
                db.execute_unprepared(&q1).await?;

                let q2 = format!(
                    "CREATE UNIQUE INDEX `{UNIQUE_INDEX_CREDENTIAL_SCHEMA_ORGANISATION_TYPE_ID_DELETED_AT_UNIQUE}` ON credential_schema(`organisation_id`,`schema_id`,`schema_type`,`deleted_at_materialized`);"
                );
                db.execute_unprepared(&q2).await?;

                let q3 =
                    format!("DROP INDEX `{SCHEMA_ID_IN_ORGANISATION_INDEX}` ON credential_schema");
                db.execute_unprepared(&q3).await?;
            }
            sea_orm::DatabaseBackend::Sqlite => {
                let q1 = format!(
                    "CREATE UNIQUE INDEX `{UNIQUE_INDEX_CREDENTIAL_SCHEMA_ORGANISATION_TYPE_ID_DELETED_AT_UNIQUE}` ON credential_schema(`organisation_id`,`schema_id`, `schema_type`, COALESCE(deleted_at, 'not_deleted'));"
                );
                db.execute_unprepared(&q1).await?;

                let q2 = format!("DROP INDEX `{SCHEMA_ID_IN_ORGANISATION_INDEX}`");
                db.execute_unprepared(&q2).await?;
            }
            _ => {}
        }

        Ok(())
    }
}
