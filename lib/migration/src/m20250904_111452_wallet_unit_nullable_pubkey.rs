use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::m20250820_084021_wallet_unit_table::{UNIQUE_WALLET_UNIT_PUBLIC_KEY_INDEX, WalletUnit};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => Ok(()),
            DbBackend::Sqlite => sqlite_migration(manager).await,
            DbBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(WalletUnit::Table)
                            .modify_column(ColumnDef::new(WalletUnit::PublicKey).string().null())
                            .to_owned(),
                    )
                    .await
            }
        }
    }
}
async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
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
                    ColumnDef::new(WalletUnitCopy::PublicKeyCopy)
                        .string()
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
                    WalletUnitCopy::PublicKeyCopy,
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
    manager
        .alter_table(
            Table::alter()
                .table(WalletUnit::Table)
                .rename_column(WalletUnitCopy::PublicKeyCopy, WalletUnit::PublicKey)
                .to_owned(),
        )
        .await?;
    // Recreate index
    manager
        .create_index(
            Index::create()
                .name(UNIQUE_WALLET_UNIT_PUBLIC_KEY_INDEX)
                .table(WalletUnit::Table)
                .col(WalletUnit::PublicKey)
                .unique()
                .to_owned(),
        )
        .await
}

#[derive(Iden)]
pub enum WalletUnitCopy {
    PublicKeyCopy,
}
