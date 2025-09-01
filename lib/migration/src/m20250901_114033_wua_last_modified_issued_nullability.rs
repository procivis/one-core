use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20250820_084021_wallet_unit_table::WalletUnit;

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
                            .modify_column(
                                ColumnDef::new(WalletUnit::LastModified)
                                    .datetime_millisecond_precision(manager)
                                    .not_null(),
                            )
                            .modify_column(
                                ColumnDef::new(WalletUnit::LastIssuance)
                                    .datetime_millisecond_precision(manager)
                                    .null(),
                            )
                            .add_column(ColumnDef::new(WalletUnitNew::Nonce).text().null())
                            .to_owned(),
                    )
                    .await
            }
        }
    }
}
async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(WalletUnit::Table)
                .add_column(
                    ColumnDef::new(WalletUnitNew::LastModifiedCopy)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(WalletUnit::Table)
                .add_column(
                    ColumnDef::new(WalletUnitNew::LastIssuanceCopy)
                        .datetime_millisecond_precision(manager)
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
                    WalletUnitNew::LastModifiedCopy,
                    SimpleExpr::Column(WalletUnit::LastModified.into_column_ref()),
                )
                .value(
                    WalletUnitNew::LastIssuanceCopy,
                    SimpleExpr::Column(WalletUnit::LastIssuance.into_column_ref()),
                )
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(WalletUnit::Table)
                .drop_column(WalletUnit::LastModified)
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(WalletUnit::Table)
                .drop_column(WalletUnit::LastIssuance)
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(WalletUnit::Table)
                .rename_column(WalletUnitNew::LastModifiedCopy, WalletUnit::LastModified)
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(WalletUnit::Table)
                .rename_column(WalletUnitNew::LastIssuanceCopy, WalletUnit::LastIssuance)
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(WalletUnit::Table)
                .add_column(ColumnDef::new(WalletUnitNew::Nonce).text().null())
                .to_owned(),
        )
        .await
}

#[derive(Iden)]
#[allow(clippy::enum_variant_names)]
pub enum WalletUnitNew {
    LastModifiedCopy,
    LastIssuanceCopy,
    Nonce,
}
