use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::Organisation;
use crate::m20250317_133346_add_org_name::UNIQUE_NAME_IN_ORGANISATION_INDEX;
use crate::m20250429_142011_add_identifier::Identifier;
use crate::m20250911_140445_add_wallet_unit_provider_config_to_org::UNIQUE_WALLET_PROVIDER_IN_ORGANISATION_INDEX;

pub const FK_ORGANISATION_PARENT_ORGANISATION: &str = "fk-Organisation-ParentOrganisation";
pub const INDEX_ORGANISATION_PARENT_ORGANISATION: &str = "index-Organisation-ParentOrganisation";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => {
                return Ok(());
            }
            DbBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Organisation::Table)
                            .add_column(
                                ColumnDef::new(OrganisationCol::ParentOrganisation)
                                    .char_len(36)
                                    .null(),
                            )
                            .add_foreign_key(
                                TableForeignKey::new()
                                    .name(FK_ORGANISATION_PARENT_ORGANISATION)
                                    .from_tbl(Organisation::Table)
                                    .from_col(OrganisationCol::ParentOrganisation)
                                    .to_tbl(Organisation::Table)
                                    .to_col(Organisation::Id)
                                    .on_delete(ForeignKeyAction::SetNull),
                            )
                            .to_owned(),
                    )
                    .await
            }
            DbBackend::Sqlite => sqlite_migration(manager).await,
            other => {
                return Err(DbErr::BackendNotSupported {
                    db: other.as_str(),
                    ctx: "migration",
                });
            }
        }?;

        manager
            .create_index(
                Index::create()
                    .name(INDEX_ORGANISATION_PARENT_ORGANISATION)
                    .table(Organisation::Table)
                    .col(OrganisationCol::ParentOrganisation)
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
                    ColumnDef::new(OrganisationCol::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(OrganisationCol::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(OrganisationCol::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(OrganisationCol::DeactivatedAt)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .col(ColumnDef::new(OrganisationCol::Name).text().not_null())
                .col(
                    ColumnDef::new(OrganisationCol::WalletProvider)
                        .string()
                        .null(),
                )
                .col(
                    ColumnDef::new(OrganisationCol::WalletProviderIssuer)
                        .char_len(36)
                        .null(),
                )
                .col(
                    ColumnDef::new(OrganisationCol::ParentOrganisation)
                        .char_len(36)
                        .null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-OrganisationWalletUnitIssuer-IssuerId")
                        .from_tbl(OrganisationNew::Table)
                        .from_col(OrganisationCol::WalletProviderIssuer)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name(FK_ORGANISATION_PARENT_ORGANISATION)
                        .from_tbl(OrganisationNew::Table)
                        .from_col(OrganisationCol::ParentOrganisation)
                        .to_tbl(OrganisationNew::Table)
                        .to_col(OrganisationCol::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        OrganisationCol::Id,
        OrganisationCol::CreatedDate,
        OrganisationCol::LastModified,
        OrganisationCol::DeactivatedAt,
        OrganisationCol::Name,
        OrganisationCol::WalletProvider,
        OrganisationCol::WalletProviderIssuer,
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
                .col(OrganisationCol::Name)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name(UNIQUE_WALLET_PROVIDER_IN_ORGANISATION_INDEX)
                .unique()
                .table(Organisation::Table)
                .col(OrganisationCol::WalletProvider)
                .to_owned(),
        )
        .await?;

    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

#[derive(DeriveIden, Copy, Clone)]
enum OrganisationNew {
    Table,
}

#[derive(DeriveIden, Copy, Clone)]
pub enum OrganisationCol {
    Id,
    CreatedDate,
    LastModified,
    DeactivatedAt,
    Name,
    WalletProvider,
    WalletProviderIssuer,
    ParentOrganisation,
}
