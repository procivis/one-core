use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::Interaction;

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
            .exec_stmt(
                Table::alter()
                    .table(Interaction::Table)
                    .drop_column(Interaction::Host)
                    .to_owned(),
            )
            .await
    }
}
