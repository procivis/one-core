use sea_orm_migration::prelude::*;

use crate::m20240130_105023_add_history::History;

#[derive(DeriveMigrationName)]
pub struct Migration;

const HISTORY_ENTITY_ID_INDEX: &str = "index-History-EntityId";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        manager
            .create_index(
                Index::create()
                    .name(HISTORY_ENTITY_ID_INDEX)
                    .table(History::Table)
                    .col(History::EntityId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
