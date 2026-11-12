use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, boolean_null};
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::migrations::m20260417_150300_initial::{
    VerifierInstance as VerifierInstanceInitial, WalletInstance as WalletInstanceInitial,
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
                    .add_column(boolean_null(WalletInstance::TrustedRpRequired))
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(WalletInstanceInitial::Table)
                    .values([(WalletInstance::TrustedRpRequired, false.into())])
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(WalletInstanceInitial::Table)
                    .modify_column(boolean(WalletInstance::TrustedRpRequired))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(VerifierInstanceInitial::Table)
                    .add_column(boolean_null(VerifierInstance::TrustedIssuerRequired))
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(VerifierInstanceInitial::Table)
                    .values([(VerifierInstance::TrustedIssuerRequired, false.into())])
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(VerifierInstanceInitial::Table)
                    .modify_column(boolean(VerifierInstance::TrustedIssuerRequired))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn up_sqlite(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .recreate_table(
                Table::recreate()
                    .table(WalletInstanceInitial::Table)
                    .add_column_with_value(
                        boolean(WalletInstance::TrustedRpRequired),
                        Expr::value(false),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .recreate_table(
                Table::recreate()
                    .table(VerifierInstanceInitial::Table)
                    .add_column_with_value(
                        boolean(VerifierInstance::TrustedIssuerRequired),
                        Expr::value(false),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum WalletInstance {
    TrustedRpRequired,
}

#[derive(DeriveIden)]
pub enum VerifierInstance {
    TrustedIssuerRequired,
}
