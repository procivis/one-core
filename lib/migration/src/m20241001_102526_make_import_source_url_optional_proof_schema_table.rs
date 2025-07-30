use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const TABLE: &str = "proof_schema";
const IMPORTED_SOURCE_URL: &str = "imported_source_url";
const TEMP_IMPORTED_SOURCE_URL: &str = "temp_imported_source_url";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        if matches!(manager.get_database_backend(), DatabaseBackend::Sqlite) {
            let conn = manager.get_connection();

            conn.execute_unprepared(&format!(
                "ALTER TABLE {TABLE} ADD COLUMN {TEMP_IMPORTED_SOURCE_URL} TEXT;",
            ))
            .await?;

            conn.execute_unprepared(&format!(
                "UPDATE {TABLE} SET {TEMP_IMPORTED_SOURCE_URL} = {IMPORTED_SOURCE_URL};",
            ))
            .await?;

            conn.execute_unprepared(&format!(
                "ALTER TABLE {TABLE} DROP COLUMN {IMPORTED_SOURCE_URL};",
            ))
            .await?;

            conn
                .execute_unprepared(&format!("ALTER TABLE {TABLE} RENAME COLUMN {TEMP_IMPORTED_SOURCE_URL} TO {IMPORTED_SOURCE_URL};"))
                .await?;

            Ok(())
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(TABLE))
                        .modify_column(
                            ColumnDef::new(Alias::new(IMPORTED_SOURCE_URL))
                                .string()
                                .null(),
                        )
                        .to_owned(),
                )
                .await
        }
    }
}
