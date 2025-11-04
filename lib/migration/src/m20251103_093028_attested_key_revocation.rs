use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::{timestamp, uuid_char, uuid_char_null};
use crate::m20250820_084021_wallet_unit_table::WalletUnit;
use crate::m20251027_101749_add_wallet_unit_attested_key::WalletUnitAttestedKey;
use crate::m20251030_110836_revocation_list_entry::RevocationListEntry;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        match &backend {
            DatabaseBackend::Postgres => {}
            DatabaseBackend::MySql => {
                let foreign_key_drop_statement = ForeignKey::drop()
                    .name("fk-WalletUnitAttestedKey-RevocationList")
                    .table(WalletUnitAttestedKey::Table)
                    .to_owned();

                manager
                    .get_connection()
                    .execute(backend.build(&foreign_key_drop_statement))
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(WalletUnitAttestedKey::Table)
                            .drop_column(WalletUnitAttestedKey::RevocationListId)
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(WalletUnitAttestedKey::Table)
                            .drop_column(WalletUnitAttestedKey::RevocationListIndex)
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(WalletUnitAttestedKey::Table)
                            .add_column(
                                ColumnDef::new(
                                    WalletUnitAttestedKeyWithListEntry::RevocationListEntryId,
                                )
                                .char_len(36)
                                .null(),
                            )
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(WalletUnitAttestedKey::Table)
                            .add_foreign_key(
                                ForeignKey::create()
                                    .name("fk-WalletUnitAttestedKey-RevocationListEntry")
                                    .from(
                                        WalletUnitAttestedKey::Table,
                                        WalletUnitAttestedKeyWithListEntry::RevocationListEntryId,
                                    )
                                    .to(RevocationListEntry::Table, RevocationListEntry::Id)
                                    .get_foreign_key(),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            DatabaseBackend::Sqlite => sqlite_migration_drop_revocation_list(manager).await?,
        };

        Ok(())
    }
}

async fn sqlite_migration_drop_revocation_list(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // Drop old table
    manager
        .drop_table(Table::drop().table(WalletUnitAttestedKey::Table).to_owned())
        .await?;

    // Create new table with the `RevocationListId` and `RevocationListIndex` column removed
    manager
        .create_table(
            Table::create()
                .table(WalletUnitAttestedKey::Table)
                .col(uuid_char(WalletUnitAttestedKey::Id).primary_key())
                .col(timestamp(WalletUnitAttestedKey::CreatedDate, manager))
                .col(timestamp(WalletUnitAttestedKey::LastModified, manager))
                .col(timestamp(WalletUnitAttestedKey::ExpirationDate, manager))
                .col(
                    ColumnDef::new(WalletUnitAttestedKey::PublicKeyJwk)
                        .text()
                        .not_null(),
                )
                .col(uuid_char(WalletUnitAttestedKey::WalletUnitId))
                .col(uuid_char_null(
                    WalletUnitAttestedKeyWithListEntry::RevocationListEntryId,
                ))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-WalletUnitAttestedKey-WalletUnit")
                        .from_tbl(WalletUnitAttestedKey::Table)
                        .from_col(WalletUnitAttestedKey::WalletUnitId)
                        .to_tbl(WalletUnit::Table)
                        .to_col(WalletUnit::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-WalletUnitAttestedKey-RevocationListEntry")
                        .from_tbl(WalletUnitAttestedKey::Table)
                        .from_col(WalletUnitAttestedKeyWithListEntry::RevocationListEntryId)
                        .to_tbl(RevocationListEntry::Table)
                        .to_col(RevocationListEntry::Id),
                )
                .take(),
        )
        .await?;

    Ok(())
}

#[derive(DeriveIden)]
pub enum WalletUnitAttestedKeyWithListEntry {
    RevocationListEntryId,
}
