use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::string_null;
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::migrations::m20260417_150300_initial::{
    HolderWalletInstance as HolderWalletInstanceInitial, WalletInstance as WalletInstanceInitial,
};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.supported_db_type() == SupportedDbType::Sqlite {
            self.up_sqlite(manager).await
        } else {
            self.up_sane(manager).await
        }
    }
}

impl Migration {
    async fn up_sane(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(HolderWalletInstanceInitial::Table)
                    .drop_column(WalletInstanceColumn::UserNonce)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(HolderWalletInstanceInitial::Table)
                    .drop_column(WalletInstanceColumn::UserSub)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(WalletInstanceInitial::Table)
                    .add_column(string_null(WalletInstanceColumn::UserNonce))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(WalletInstanceInitial::Table)
                    .add_column(string_null(WalletInstanceColumn::UserSub))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn up_sqlite(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .recreate_table(
                Table::recreate()
                    .table(HolderWalletInstanceInitial::Table)
                    .drop_column(WalletInstanceColumn::UserNonce)
                    .drop_column(WalletInstanceColumn::UserSub)
                    .to_owned(),
            )
            .await?;

        // Add user_nonce and user_sub to wallet_instance
        manager
            .alter_table(
                Table::alter()
                    .table(WalletInstanceInitial::Table)
                    .add_column(string_null(WalletInstanceColumn::UserNonce))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(WalletInstanceInitial::Table)
                    .add_column(string_null(WalletInstanceColumn::UserSub))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum WalletInstanceColumn {
    UserNonce,
    UserSub,
}
