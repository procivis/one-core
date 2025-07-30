use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::Organisation;
use crate::m20240130_105023_add_history::History;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => Ok(()),
            DbBackend::Sqlite => sqlite_migration(manager).await,
            DbBackend::MySql => sane_migration(manager).await,
        }
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(HistoryNew::Table)
                .col(
                    ColumnDef::new(HistoryNew::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(HistoryNew::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(ColumnDef::new(HistoryNew::Action).text().not_null())
                .col(ColumnDef::new(HistoryNew::EntityId).char_len(36))
                .col(ColumnDef::new(HistoryNew::EntityType).text().not_null())
                .col(ColumnDef::new(HistoryNew::OrganisationId).char_len(36))
                .col(ColumnDef::new(HistoryNew::Metadata).text())
                .col(
                    ColumnDef::new(HistoryNew::Name)
                        .text()
                        .default("")
                        .not_null(),
                )
                .col(ColumnDef::new(HistoryNew::Target).text())
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-History-OrganisationId")
                        .from_tbl(HistoryNew::Table)
                        .from_col(History::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    let connection = manager.get_connection();
    connection
        .execute_unprepared("INSERT INTO history_new SELECT * FROM history")
        .await?;

    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = ON; DROP TABLE `history`; ALTER TABLE `history_new` RENAME TO `history`; PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

async fn sane_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(History::Table)
                .modify_column(ColumnDef::new(History::OrganisationId).char_len(36))
                .to_owned(),
        )
        .await
}

#[derive(DeriveIden)]
pub enum HistoryNew {
    Table,
    Id,
    CreatedDate,
    Action,
    EntityId,
    EntityType,
    OrganisationId,
    Metadata,
    Name,
    Target,
}
