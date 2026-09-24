use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::{timestamp, uuid_char, uuid_char_null};
use crate::m20240110_000001_initial::Organisation;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres => {}
            DatabaseBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(History::Table)
                            .add_column_if_not_exists(
                                ColumnDef::new(History::MetadataBlobId).char_len(36).null(),
                            )
                            .add_foreign_key(
                                TableForeignKey::new()
                                    .name("fk-History-MetadataBlobId")
                                    .from_tbl(History::Table)
                                    .from_col(History::MetadataBlobId)
                                    .to_tbl(BlobStorage::Table)
                                    .to_col(BlobStorage::Id)
                                    .on_delete(ForeignKeyAction::SetNull),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            DatabaseBackend::Sqlite => {
                sqlite_migration(manager).await?;
            }
            other => {
                return Err(DbErr::BackendNotSupported {
                    db: other.as_str(),
                    ctx: "migration",
                });
            }
        }

        Ok(())
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with all existing columns + metadata_blob_id with FK
    manager
        .create_table(
            Table::create()
                .table(HistoryNew::Table)
                .col(uuid_char(History::Id).primary_key())
                .col(timestamp(History::CreatedDate, manager))
                .col(ColumnDef::new(History::Action).string().not_null())
                .col(uuid_char_null(History::EntityId))
                .col(ColumnDef::new(History::EntityType).string().not_null())
                .col(ColumnDef::new(History::Metadata).text().null())
                .col(ColumnDef::new(History::Name).string().not_null())
                .col(ColumnDef::new(History::Source).string().not_null())
                .col(ColumnDef::new(History::Target).string().null())
                .col(ColumnDef::new(History::User).string().null())
                .col(uuid_char_null(History::OrganisationId))
                .col(uuid_char_null(History::MetadataBlobId))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-History-OrganisationId-new")
                        .from_tbl(HistoryNew::Table)
                        .from_col(History::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-History-MetadataBlobId")
                        .from_tbl(HistoryNew::Table)
                        .from_col(History::MetadataBlobId)
                        .to_tbl(BlobStorage::Table)
                        .to_col(BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        History::Id,
        History::CreatedDate,
        History::Action,
        History::EntityId,
        History::EntityType,
        History::Metadata,
        History::Name,
        History::Source,
        History::Target,
        History::User,
        History::OrganisationId,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(HistoryNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(History::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(History::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(HistoryNew::Table, History::Table)
                .to_owned(),
        )
        .await?;

    // Recreate indexes
    manager
        .create_index(
            Index::create()
                .name("index-History-EntityId")
                .table(History::Table)
                .col(History::EntityId)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-History-Metadata")
                .table(History::Table)
                .col(History::Metadata)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-History-CreatedDate")
                .table(History::Table)
                .col(History::CreatedDate)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-History-Org-CreatedDate")
                .table(History::Table)
                .col(History::OrganisationId)
                .col(History::CreatedDate)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

#[derive(Clone, DeriveIden)]
enum History {
    Table,
    Id,
    CreatedDate,
    Action,
    EntityId,
    EntityType,
    Metadata,
    Name,
    Source,
    Target,
    User,
    OrganisationId,
    MetadataBlobId,
}

#[derive(DeriveIden)]
enum HistoryNew {
    Table,
}

#[derive(DeriveIden)]
enum BlobStorage {
    Table,
    Id,
}
