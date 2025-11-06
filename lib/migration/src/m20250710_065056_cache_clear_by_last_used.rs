use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => {}
            DbBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(RemoteEntityCache::Table)
                            .drop_column(RemoteEntityCache::HitCounter)
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(RemoteEntityCache::Table)
                            .add_column(
                                ColumnDef::new(RemoteEntityCache::LastUsed)
                                    .datetime_millisecond_precision(manager)
                                    .not_null()
                                    .default(Expr::current_timestamp()),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            DbBackend::Sqlite => {
                sqlite_migration(manager).await?;
            }
        }
        Ok(())
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(NewRemoteEntityCache::Table)
                .col(
                    ColumnDef::new(NewRemoteEntityCache::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(NewRemoteEntityCache::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(NewRemoteEntityCache::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(NewRemoteEntityCache::Value)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(NewRemoteEntityCache::Key)
                        .string_len(4096)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(NewRemoteEntityCache::Type)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(NewRemoteEntityCache::MediaType)
                        .string()
                        .null(),
                )
                .col(
                    ColumnDef::new(NewRemoteEntityCache::ExpirationDate)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .col(
                    ColumnDef::new(NewRemoteEntityCache::LastUsed)
                        .datetime_millisecond_precision(manager)
                        .not_null()
                        .default(Expr::current_timestamp()),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = [
        NewRemoteEntityCache::Id,
        NewRemoteEntityCache::CreatedDate,
        NewRemoteEntityCache::LastModified,
        NewRemoteEntityCache::Value,
        NewRemoteEntityCache::Key,
        NewRemoteEntityCache::Type,
        NewRemoteEntityCache::MediaType,
        NewRemoteEntityCache::ExpirationDate,
    ];

    manager
        .exec_stmt(
            Query::insert()
                .into_table(NewRemoteEntityCache::Table)
                .columns(copied_columns)
                .select_from(
                    Query::select()
                        .from(RemoteEntityCache::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Disable foreign keys for SQLite
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    manager
        .drop_table(Table::drop().table(RemoteEntityCache::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(NewRemoteEntityCache::Table, RemoteEntityCache::Table)
                .to_owned(),
        )
        .await?;

    // Enable foreign keys for SQLite
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

#[derive(DeriveIden)]
enum RemoteEntityCache {
    Table,
    HitCounter,
    LastUsed,
}

#[derive(DeriveIden, Clone, Copy)]
pub(crate) enum NewRemoteEntityCache {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Value,
    Key,
    Type,
    MediaType,
    ExpirationDate,
    LastUsed,
}
