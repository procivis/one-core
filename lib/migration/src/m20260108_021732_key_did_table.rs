use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::datatype::uuid_char;
use crate::m20240110_000001_initial::{Did, Key};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres | DatabaseBackend::MySql => {}
            DatabaseBackend::Sqlite => sqlite_migration(manager).await?,
        };

        Ok(())
    }
}

#[derive(Iden)]
enum KeyDidNew {
    Table,
}

#[derive(Clone, Iden)]
enum KeyDid {
    Table,
    DidId,
    KeyId,
    Role,
    Reference,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the correct columns
    manager
        .create_table(
            Table::create()
                .table(KeyDidNew::Table)
                .col(uuid_char(KeyDid::DidId))
                .col(uuid_char(KeyDid::KeyId))
                .col(string(KeyDid::Role))
                .col(string_len(KeyDid::Reference, 4000))
                .primary_key(
                    Index::create()
                        .name("pk-KeyDid")
                        .col(KeyDid::DidId)
                        .col(KeyDid::KeyId)
                        .col(KeyDid::Role)
                        .primary(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-KeyDid-DidId")
                        .from_tbl(KeyDidNew::Table)
                        .from_col(KeyDid::DidId)
                        .to_tbl(Did::Table)
                        .to_col(Did::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-KeyDid-KeyId")
                        .from_tbl(KeyDidNew::Table)
                        .from_col(KeyDid::KeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        KeyDid::DidId,
        KeyDid::KeyId,
        KeyDid::Role,
        KeyDid::Reference,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(KeyDidNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(KeyDid::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(KeyDid::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(KeyDidNew::Table, KeyDid::Table)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
