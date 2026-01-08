use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::string;

use crate::datatype::{ColumnDefExt, timestamp, uuid_char};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres => {}
            DatabaseBackend::MySql => {
                // change type
                manager
                    .alter_table(
                        Table::alter()
                            .table(BlobStorage::Table)
                            .modify_column(string(BlobStorage::Type))
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
enum BlobStorageNew {
    Table,
}

#[derive(Clone, Iden)]
enum BlobStorage {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Value,
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
                .table(BlobStorageNew::Table)
                .col(uuid_char(BlobStorage::Id).primary_key())
                .col(timestamp(BlobStorage::CreatedDate, manager))
                .col(timestamp(BlobStorage::LastModified, manager))
                .col(
                    ColumnDef::new(BlobStorage::Value)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(string(BlobStorage::Type))
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        BlobStorage::Id,
        BlobStorage::CreatedDate,
        BlobStorage::LastModified,
        BlobStorage::Value,
        BlobStorage::Type,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(BlobStorageNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(BlobStorage::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(BlobStorage::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(BlobStorageNew::Table, BlobStorage::Table)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
