use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::RevocationList;
use crate::m20250820_084021_wallet_unit_table::UNIQUE_WALLET_UNIT_PUBLIC_KEY_INDEX;
use crate::m20250911_133704_add_org_to_wallet_unit::WalletUnit;

#[derive(DeriveMigrationName)]
pub struct Migration;

pub const UNIQUE_WALLET_UNIT_ORG_AUTH_KEY_INDEX: &str =
    "index-WalletUnit-Organisation-AuthenticationKey-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .create_table(
                Table::create()
                    .table(WalletUnitAttestedKey::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WalletUnitAttestedKey::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestedKey::CreatedDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestedKey::LastModified)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestedKey::ExpirationDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestedKey::PublicKeyJwk)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestedKey::WalletUnitId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestedKey::RevocationListId)
                            .char_len(36)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestedKey::RevocationListIndex)
                            .integer()
                            .unsigned()
                            .null(),
                    )
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
                            .name("fk-WalletUnitAttestedKey-RevocationList")
                            .from_tbl(WalletUnitAttestedKey::Table)
                            .from_col(WalletUnitAttestedKey::RevocationListId)
                            .to_tbl(RevocationList::Table)
                            .to_col(RevocationList::Id),
                    )
                    .to_owned(),
            )
            .await?;

        wallet_unit_auth_key_migration(manager).await
    }
}

async fn wallet_unit_auth_key_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .drop_index(
            Index::drop()
                .name(UNIQUE_WALLET_UNIT_PUBLIC_KEY_INDEX)
                .table(WalletUnit::Table)
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(WalletUnit::Table)
                .add_column(
                    ColumnDef::new(WalletUnitNew::AuthenticationKeyJwk)
                        .text()
                        .null(),
                )
                .to_owned(),
        )
        .await?;

    manager
        .exec_stmt(
            Query::update()
                .table(WalletUnit::Table)
                .value(
                    WalletUnitNew::AuthenticationKeyJwk,
                    SimpleExpr::Column(WalletUnit::PublicKey.into_column_ref()),
                )
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(WalletUnit::Table)
                .drop_column(WalletUnit::PublicKey)
                .to_owned(),
        )
        .await?;

    // Recreate index, but include organisation_id
    manager
        .create_index(
            Index::create()
                .name(UNIQUE_WALLET_UNIT_ORG_AUTH_KEY_INDEX)
                .table(WalletUnit::Table)
                .col(WalletUnitNew::AuthenticationKeyJwk)
                .col(WalletUnit::OrganisationId)
                .unique()
                .to_owned(),
        )
        .await
}

#[derive(Iden)]
pub enum WalletUnitNew {
    AuthenticationKeyJwk,
}

#[derive(DeriveIden)]
enum WalletUnitAttestedKey {
    Table,
    Id,
    WalletUnitId,
    CreatedDate,
    LastModified,
    ExpirationDate,
    PublicKeyJwk,
    RevocationListId,
    RevocationListIndex,
}
