use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::Organisation;
use crate::m20250317_133346_add_org_name::UNIQUE_NAME_IN_ORGANISATION_INDEX;
use crate::m20250429_142011_add_identifier::Identifier;

pub const UNIQUE_WALLET_PROVIDER_IN_ORGANISATION_INDEX: &str =
    "index-Organisation-WalletProvider-Unique";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => {
                // Skip because it is not supported. If support for Postgres is added in the future
                // the schema can be setup in its entirety in a new, later migration.
                Ok(())
            }
            DbBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Organisation::Table)
                            .add_column(
                                ColumnDef::new(OrganisationNew::WalletProvider)
                                    .string()
                                    .null(),
                            )
                            .to_owned(),
                    )
                    .await?;
                manager
                    .alter_table(
                        Table::alter()
                            .table(Organisation::Table)
                            .add_column(
                                ColumnDef::new(OrganisationNew::WalletProviderIssuer)
                                    .char_len(36)
                                    .null(),
                            )
                            .add_foreign_key(
                                TableForeignKey::new()
                                    .name("fk-OrganisationWalletUnitIssuer-IssuerId")
                                    .from_tbl(Organisation::Table)
                                    .from_col(OrganisationNew::WalletProviderIssuer)
                                    .to_tbl(Identifier::Table)
                                    .to_col(Identifier::Id),
                            )
                            .to_owned(),
                    )
                    .await
            }
            DbBackend::Sqlite => sqlite_migration(manager).await,
        }?;

        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_WALLET_PROVIDER_IN_ORGANISATION_INDEX)
                    .unique()
                    .table(Organisation::Table)
                    .col(OrganisationNew::WalletProvider)
                    .to_owned(),
            )
            .await
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(OrganisationNew::Table)
                .col(
                    ColumnDef::new(OrganisationNew::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(OrganisationNew::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(OrganisationNew::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(OrganisationNew::DeactivatedAt)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .col(ColumnDef::new(OrganisationNew::Name).text().not_null())
                .col(
                    ColumnDef::new(OrganisationNew::WalletProvider)
                        .string()
                        .null(),
                )
                .col(
                    ColumnDef::new(OrganisationNew::WalletProviderIssuer)
                        .char_len(36)
                        .null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-OrganisationWalletUnitIssuer-IssuerId")
                        .from_tbl(OrganisationNew::Table)
                        .from_col(OrganisationNew::WalletProviderIssuer)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        OrganisationNew::Id,
        OrganisationNew::CreatedDate,
        OrganisationNew::LastModified,
        OrganisationNew::DeactivatedAt,
        OrganisationNew::Name,
    ];

    manager
        .exec_stmt(
            Query::insert()
                .into_table(OrganisationNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(Organisation::Table)
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
        .drop_table(Table::drop().table(Organisation::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(OrganisationNew::Table, Organisation::Table)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name(UNIQUE_NAME_IN_ORGANISATION_INDEX)
                .unique()
                .table(Organisation::Table)
                .col(OrganisationNew::Name)
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

#[derive(DeriveIden, Copy, Clone)]
enum OrganisationNew {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeactivatedAt,
    Name,
    WalletProvider,
    WalletProviderIssuer,
}
