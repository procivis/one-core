use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UNIQUE_WALLET_UNIT_PUBLIC_KEY_INDEX: &str = "index-WalletUnit-PublicKey-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .create_table(
                Table::create()
                    .table(WalletUnit::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WalletUnit::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(WalletUnit::CreatedDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnit::LastModified)
                            .datetime_millisecond_precision(manager),
                    )
                    .col(
                        ColumnDef::new(WalletUnit::LastIssuance)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(ColumnDef::new(WalletUnit::Name).string().not_null())
                    .col(ColumnDef::new(WalletUnit::Os).string().not_null())
                    .col(ColumnDef::new(WalletUnit::Status).string().not_null())
                    .col(
                        ColumnDef::new(WalletUnit::WalletUnitType)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(WalletUnit::PublicKey).string().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_WALLET_UNIT_PUBLIC_KEY_INDEX)
                    .table(WalletUnit::Table)
                    .col(WalletUnit::PublicKey)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(WalletUnit::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
#[allow(clippy::enum_variant_names)]
pub enum WalletUnit {
    Table,
    Id,
    CreatedDate,
    LastModified,
    LastIssuance,
    Name,
    Os,
    Status,
    WalletUnitType,
    PublicKey,
}
