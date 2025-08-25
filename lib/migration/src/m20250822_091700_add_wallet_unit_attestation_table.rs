use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::{Key, Organisation};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    #[allow(unreachable_code, unused_variables)]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .create_table(
                Table::create()
                    .table(WalletUnitAttestation::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WalletUnitAttestation::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestation::CreatedDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestation::LastModified)
                            .datetime_millisecond_precision(manager),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestation::ExpirationDate)
                            .datetime_millisecond_precision(manager)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestation::Status)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestation::Attestation)
                            .large_blob(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestation::WalletUnitId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestation::WalletProviderUrl)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestation::WalletProviderType)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestation::WalletProviderName)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestation::OrganisationId)
                            .char_len(36)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnitAttestation::KeyId)
                            .char_len(36)
                            .null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-WalletUnitAttestation-KeyId")
                            .from_tbl(WalletUnitAttestation::Table)
                            .from_col(WalletUnitAttestation::KeyId)
                            .to_tbl(Key::Table)
                            .to_col(Key::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-WalletUnitAttestation-OrganisationId")
                            .from_tbl(WalletUnitAttestation::Table)
                            .from_col(WalletUnitAttestation::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(WalletUnitAttestation::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
#[allow(clippy::enum_variant_names)]
pub enum WalletUnitAttestation {
    Table,
    Id,
    CreatedDate,
    LastModified,
    ExpirationDate,
    Status,
    Attestation,
    WalletUnitId,
    WalletProviderUrl,
    WalletProviderType,
    WalletProviderName,
    OrganisationId,
    KeyId,
}
