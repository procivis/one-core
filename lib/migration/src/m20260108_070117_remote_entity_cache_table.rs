use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_len, string_null};

use crate::datatype::{ColumnDefExt, timestamp, timestamp_null, uuid_char};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres => {}
            DatabaseBackend::MySql => {
                // remove default value
                manager
                    .alter_table(
                        Table::alter()
                            .table(RemoteEntityCache::Table)
                            .modify_column(timestamp(RemoteEntityCache::LastUsed, manager))
                            .to_owned(),
                    )
                    .await?;

                // recreate index
                manager
                    .drop_index(
                        Index::drop()
                            .name("index-RemoteEntityCache-Type-ExpirationDate")
                            .table(RemoteEntityCache::Table)
                            .to_owned(),
                    )
                    .await?;

                manager
                    .create_index(
                        Index::create()
                            .name("index-RemoteEntityCache-Type-ExpirationDate")
                            .table(RemoteEntityCache::Table)
                            .col(RemoteEntityCache::Type)
                            .col(RemoteEntityCache::ExpirationDate)
                            .to_owned(),
                    )
                    .await?;
            }
            DatabaseBackend::Sqlite => sqlite_migration(manager).await?,
        };

        Ok(())
    }
}

#[derive(Iden)]
enum RemoteEntityCacheNew {
    Table,
}

#[derive(Clone, Iden)]
enum RemoteEntityCache {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Value,
    Key,
    MediaType,
    ExpirationDate,
    LastUsed,
    Type,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the correct columns
    manager
        .create_table(
            Table::create()
                .table(RemoteEntityCacheNew::Table)
                .col(uuid_char(RemoteEntityCache::Id).primary_key())
                .col(timestamp(RemoteEntityCache::CreatedDate, manager))
                .col(timestamp(RemoteEntityCache::LastModified, manager))
                .col(
                    ColumnDef::new(RemoteEntityCache::Value)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(string_len(RemoteEntityCache::Key, 4096))
                .col(string_null(RemoteEntityCache::MediaType))
                .col(timestamp_null(RemoteEntityCache::ExpirationDate, manager))
                .col(timestamp(RemoteEntityCache::LastUsed, manager))
                .col(string(RemoteEntityCache::Type))
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        RemoteEntityCache::Id,
        RemoteEntityCache::CreatedDate,
        RemoteEntityCache::LastModified,
        RemoteEntityCache::Value,
        RemoteEntityCache::Key,
        RemoteEntityCache::MediaType,
        RemoteEntityCache::ExpirationDate,
        RemoteEntityCache::LastUsed,
        RemoteEntityCache::Type,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(RemoteEntityCacheNew::Table)
                .columns(copied_columns.to_vec())
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

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(RemoteEntityCache::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(RemoteEntityCacheNew::Table, RemoteEntityCache::Table)
                .to_owned(),
        )
        .await?;

    // Recreate indexes
    manager
        .create_index(
            Index::create()
                .unique()
                .name("index-RemoteEntityCache-Key-Unique")
                .table(RemoteEntityCache::Table)
                .col(RemoteEntityCache::Key)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-RemoteEntityCache-Type-ExpirationDate")
                .table(RemoteEntityCache::Table)
                .col(RemoteEntityCache::Type)
                .col(RemoteEntityCache::ExpirationDate)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
