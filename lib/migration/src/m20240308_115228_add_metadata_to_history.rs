use sea_orm_migration::prelude::*;

use crate::m20240130_105023_add_history::History;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(History::Table)
                    .add_column(ColumnDef::new(HistoryNew::Metadata).string())
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum HistoryNew {
    Metadata,
}
