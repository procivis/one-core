use sea_orm_migration::prelude::*;

const CREDENTIAL_SCHEMA_TABLE: &str = "credential_schema";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "UPDATE {CREDENTIAL_SCHEMA_TABLE} SET format = 'SD_JWT' WHERE format = 'SDJWT'"
            ))
            .await?;

        Ok(())
    }
}
