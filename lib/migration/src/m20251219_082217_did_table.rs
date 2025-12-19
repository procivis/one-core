use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, string};

use crate::datatype::{timestamp, timestamp_null, uuid_char, uuid_char_null};
use crate::m20240110_000001_initial::Organisation;

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
enum DidNew {
    Table,
}

#[derive(Clone, Iden)]
#[expect(clippy::enum_variant_names)]
enum Did {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Did,
    Name,
    Type,
    Method,
    OrganisationId,
    Deactivated,
    DeletedAt,
    Log,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the correct columns
    manager
        .create_table(
            Table::create()
                .table(DidNew::Table)
                .col(uuid_char(Did::Id).primary_key())
                .col(timestamp(Did::CreatedDate, manager))
                .col(timestamp(Did::LastModified, manager))
                .col(ColumnDef::new(Did::Did).string_len(4000).not_null())
                .col(string(Did::Name))
                .col(string(Did::Type))
                .col(string(Did::Method))
                .col(uuid_char_null(Did::OrganisationId))
                .col(boolean(Did::Deactivated))
                .col(timestamp_null(Did::DeletedAt, manager))
                .col(ColumnDef::new(Did::Log).text().null())
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Did-OrganisationId")
                        .from_tbl(DidNew::Table)
                        .from_col(Did::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        Did::Id,
        Did::CreatedDate,
        Did::LastModified,
        Did::Did,
        Did::Name,
        Did::Type,
        Did::Method,
        Did::OrganisationId,
        Did::Deactivated,
        Did::DeletedAt,
        Did::Log,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(DidNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(Did::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(Did::Table).to_owned())
        .await?;

    manager
        .rename_table(Table::rename().table(DidNew::Table, Did::Table).to_owned())
        .await?;

    // Recreate indexes
    manager.get_connection().execute_unprepared(
        "CREATE UNIQUE INDEX `index_Did_Name-OrganisationId-DeletedAt_Unique` ON `did`(`name`, `organisation_id`, COALESCE(deleted_at, 'not_deleted'));"
    ).await?;

    manager.get_connection().execute_unprepared(
        "CREATE UNIQUE INDEX `index-Did-Did-OrganisationId-Unique` ON `did`(`did`, COALESCE(organisation_id, 'no_organisation'));"
    ).await?;

    manager
        .create_index(
            Index::create()
                .name("index-Did-CreatedDate")
                .table(Did::Table)
                .col(Did::CreatedDate)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Did-Did")
                .table(Did::Table)
                .col(Did::Did)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
