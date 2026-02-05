use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::datatype::{ColumnDefExt, timestamp, uuid_char};
use crate::m20240110_000001_initial::Credential;

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
enum ValidityCredentialNew {
    Table,
}

#[derive(Clone, Iden)]
pub(crate) enum ValidityCredential {
    Table,
    Id,
    CreatedDate,
    Credential,
    CredentialId,
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
                .table(ValidityCredentialNew::Table)
                .col(uuid_char(ValidityCredential::Id).primary_key())
                .col(timestamp(ValidityCredential::CreatedDate, manager))
                .col(
                    ColumnDef::new(ValidityCredential::Credential)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(uuid_char(ValidityCredential::CredentialId))
                .col(string(ValidityCredential::Type))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Lvvc-CredentialId")
                        .from_tbl(ValidityCredentialNew::Table)
                        .from_col(ValidityCredential::CredentialId)
                        .to_tbl(Credential::Table)
                        .to_col(Credential::Id),
                )
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        ValidityCredential::Id,
        ValidityCredential::CreatedDate,
        ValidityCredential::Credential,
        ValidityCredential::CredentialId,
        ValidityCredential::Type,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(ValidityCredentialNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(ValidityCredential::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(ValidityCredential::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(ValidityCredentialNew::Table, ValidityCredential::Table)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
