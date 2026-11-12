use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, boolean_null};
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
                    .table(WalletInstanceInitial::Table)
                    .drop_column(Alias::new("trusted_rp_required"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(HolderWalletInstanceInitial::Table)
                    .add_column(boolean_null(HolderWalletInstance::TrustedRpRequired))
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(HolderWalletInstanceInitial::Table)
                    .values([(HolderWalletInstance::TrustedRpRequired, false.into())])
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(HolderWalletInstanceInitial::Table)
                    .modify_column(boolean(HolderWalletInstance::TrustedRpRequired))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn up_sqlite(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        // WalletInstance
        manager
            .alter_table(
                Table::alter()
                    .table(WalletInstanceInitial::Table)
                    .drop_column(Alias::new("trusted_rp_required"))
                    .to_owned(),
            )
            .await?;

        manager
            .recreate_table(
                Table::recreate()
                    .table(HolderWalletInstanceInitial::Table)
                    .add_column_with_value(
                        boolean(HolderWalletInstance::TrustedRpRequired),
                        Expr::value(false),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum HolderWalletInstance {
    TrustedRpRequired,
}
