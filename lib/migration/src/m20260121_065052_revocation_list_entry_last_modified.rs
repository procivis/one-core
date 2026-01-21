use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_null, unsigned_null, var_binary_null};

use crate::datatype::{timestamp, timestamp_null, uuid_char, uuid_char_null};
use crate::m20240110_000001_initial::{Credential, RevocationList};

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
                            .table(RevocationListEntry::Table)
                            // add `last_modified`
                            .add_column(timestamp_null(RevocationListEntry::LastModified, manager))
                            .to_owned(),
                    )
                    .await?;

                // copy values from `created_date`
                manager
                    .exec_stmt(
                        Query::update()
                            .table(RevocationListEntry::Table)
                            .value(
                                RevocationListEntry::LastModified,
                                SimpleExpr::Column(
                                    RevocationListEntry::CreatedDate.into_column_ref(),
                                ),
                            )
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(RevocationListEntry::Table)
                            // make `last_modified` mandatory
                            .modify_column(timestamp(RevocationListEntry::LastModified, manager))
                            .to_owned(),
                    )
                    .await?;
            }
            DatabaseBackend::Sqlite => {
                sqlite_migration(manager).await?;
            }
        }

        Ok(())
    }
}

#[derive(DeriveIden)]
enum RevocationListEntryNew {
    Table,
}

#[derive(DeriveIden, Clone)]
enum RevocationListEntry {
    Table,
    Id,
    CreatedDate,
    LastModified,
    RevocationListId,
    Index,
    CredentialId,
    Status,
    Type,
    SignatureType,
    Serial,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the correct columns
    manager
        .create_table(
            Table::create()
                .table(RevocationListEntryNew::Table)
                .col(uuid_char(RevocationListEntry::Id).primary_key())
                .col(timestamp(RevocationListEntry::CreatedDate, manager))
                .col(timestamp(RevocationListEntry::LastModified, manager))
                .col(uuid_char(RevocationListEntry::RevocationListId))
                .col(unsigned_null(RevocationListEntry::Index))
                .col(uuid_char_null(RevocationListEntry::CredentialId))
                .col(string(RevocationListEntry::Status))
                .col(string(RevocationListEntry::Type))
                .col(string_null(RevocationListEntry::SignatureType))
                .col(var_binary_null(RevocationListEntry::Serial, 20))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-RevocationListEntry-RevocationListId")
                        .from_tbl(RevocationListEntry::Table)
                        .from_col(RevocationListEntry::RevocationListId)
                        .to_tbl(RevocationList::Table)
                        .to_col(RevocationList::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-RevocationListEntry-CredentialId")
                        .from_tbl(RevocationListEntry::Table)
                        .from_col(RevocationListEntry::CredentialId)
                        .to_tbl(Credential::Table)
                        .to_col(Credential::Id),
                )
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let shared_copied_columns = vec![
        RevocationListEntry::Id,
        RevocationListEntry::CreatedDate,
        RevocationListEntry::RevocationListId,
        RevocationListEntry::Index,
        RevocationListEntry::CredentialId,
        RevocationListEntry::Status,
        RevocationListEntry::Type,
        RevocationListEntry::SignatureType,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(RevocationListEntryNew::Table)
                .columns(
                    [
                        [RevocationListEntry::LastModified].as_slice(),
                        shared_copied_columns.as_slice(),
                    ]
                    .concat(),
                )
                .select_from(
                    Query::select()
                        .from(RevocationListEntry::Table)
                        .columns(
                            [
                                [RevocationListEntry::CreatedDate].as_slice(),
                                shared_copied_columns.as_slice(),
                            ]
                            .concat(),
                        )
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(RevocationListEntry::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(RevocationListEntryNew::Table, RevocationListEntry::Table)
                .to_owned(),
        )
        .await?;

    // Recreate indexes
    manager
        .create_index(
            Index::create()
                .name("index-RevocationList-Index-Unique")
                .unique()
                .table(RevocationListEntry::Table)
                .col(RevocationListEntry::RevocationListId)
                .col(RevocationListEntry::Index)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-RevocationList-Serial-Unique")
                .unique()
                .table(RevocationListEntry::Table)
                .col(RevocationListEntry::RevocationListId)
                .col(RevocationListEntry::Serial)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
