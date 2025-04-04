use sea_orm_migration::prelude::*;

use crate::m20240130_105023_add_history::History;

#[derive(DeriveMigrationName)]
pub struct Migration;

const HISTORY_ENTITY_ID_INDEX: &str = "index-History-EntityId";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
