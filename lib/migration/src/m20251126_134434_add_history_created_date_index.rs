use sea_orm_migration::prelude::*;

use crate::m20240130_105023_add_history::History;

#[derive(DeriveMigrationName)]
pub struct Migration;

const HISTORY_CREATED_DATE_INDEX: &str = "index-History-CreatedDate";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .create_index(
                Index::create()
                    .name(HISTORY_CREATED_DATE_INDEX)
                    .table(History::Table)
                    .col(History::CreatedDate)
                    .to_owned(),
            )
            .await
    }
}
