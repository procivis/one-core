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
                            .table(RevocationList::Table)
                            .drop_foreign_key(Alias::new("fk-RevocationList-IssuerDidId"))
                            .drop_column(RevocationList::IssuerDidId)
                            .to_owned(),
                    )
                    .await?
            }
            DbBackend::Sqlite => sqlite_migration(manager).await?,
        }
        Ok(())
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(NewRevocationList::Table)
                .col(
                    ColumnDef::new(NewRevocationList::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(NewRevocationList::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(NewRevocationList::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(NewRevocationList::Credentials)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(NewRevocationList::IssuerIdentifierId)
                        .char_len(36)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(NewRevocationList::Format)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(NewRevocationList::Purpose)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(NewRevocationList::Type).string().not_null())
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk_revocation_list_issuer_identifier_id")
                        .from_tbl(NewRevocationList::Table)
                        .from_col(NewRevocationList::IssuerIdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = [
        NewRevocationList::Id,
        NewRevocationList::CreatedDate,
        NewRevocationList::LastModified,
        NewRevocationList::IssuerIdentifierId,
        NewRevocationList::Credentials,
        NewRevocationList::Purpose,
        NewRevocationList::Format,
        NewRevocationList::Type,
    ];

    manager
        .exec_stmt(
            Query::insert()
                .into_table(NewRevocationList::Table)
                .columns(copied_columns)
                .select_from(
                    Query::select()
                        .from(RevocationList::Table)
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
        .drop_table(Table::drop().table(RevocationList::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(NewRevocationList::Table, RevocationList::Table)
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
enum RevocationList {
    Table,
    IssuerDidId,
}

#[derive(DeriveIden, Clone, Copy)]
pub enum NewRevocationList {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Credentials,
    IssuerIdentifierId,
    Purpose,
    Format,
    Type,
}

#[derive(DeriveIden)]
enum Identifier {
    Table,
    Id,
}
