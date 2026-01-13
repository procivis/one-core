use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, string, text};

use crate::datatype::{timestamp, uuid_char};

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
                            .table(TrustAnchor::Table)
                            .modify_column(string(TrustAnchor::Type))
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
enum TrustAnchorNew {
    Table,
}

#[derive(Clone, Iden)]
enum TrustAnchor {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Name,
    Type,
    IsPublisher,
    PublisherReference,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the correct columns
    manager
        .create_table(
            Table::create()
                .table(TrustAnchorNew::Table)
                .col(uuid_char(TrustAnchor::Id).primary_key())
                .col(timestamp(TrustAnchor::CreatedDate, manager))
                .col(timestamp(TrustAnchor::LastModified, manager))
                .col(text(TrustAnchor::Name))
                .col(string(TrustAnchor::Type))
                .col(boolean(TrustAnchor::IsPublisher))
                .col(text(TrustAnchor::PublisherReference))
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        TrustAnchor::Id,
        TrustAnchor::CreatedDate,
        TrustAnchor::LastModified,
        TrustAnchor::Name,
        TrustAnchor::Type,
        TrustAnchor::IsPublisher,
        TrustAnchor::PublisherReference,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(TrustAnchorNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(TrustAnchor::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(TrustAnchor::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(TrustAnchorNew::Table, TrustAnchor::Table)
                .to_owned(),
        )
        .await?;

    // Recreate indexes
    manager
        .create_index(
            Index::create()
                .unique()
                .name("UK-TrustAnchor-Name")
                .table(TrustAnchor::Table)
                .col(TrustAnchor::Name)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
