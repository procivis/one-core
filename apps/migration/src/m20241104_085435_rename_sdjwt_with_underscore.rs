use sea_orm_migration::prelude::*;

const CREDENTIAL_SCHEMA_TABLE: &str = "credential_schema";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "UPDATE {} SET format = 'SD_JWT' WHERE format = 'SDJWT'",
                CREDENTIAL_SCHEMA_TABLE
            ))
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // nothing to do
        Ok(())
    }
}
