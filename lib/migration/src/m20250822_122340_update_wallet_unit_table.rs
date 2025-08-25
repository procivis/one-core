use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    #[allow(unreachable_code, unused_variables)]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            return Ok(());
        }

        // Add WalletProviderType column
        manager
            .alter_table(
                Table::alter()
                    .table(WalletUnit::Table)
                    .add_column(
                        ColumnDef::new(WalletUnit::WalletProviderType)
                            .string()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add WalletProviderName column
        manager
            .alter_table(
                Table::alter()
                    .table(WalletUnit::Table)
                    .add_column(
                        ColumnDef::new(WalletUnit::WalletProviderName)
                            .string()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Drop the old WalletUnitType column
        manager
            .alter_table(
                Table::alter()
                    .table(WalletUnit::Table)
                    .drop_column(WalletUnit::WalletUnitType)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
#[allow(clippy::enum_variant_names)]
enum WalletUnit {
    Table,
    WalletUnitType,
    WalletProviderType,
    WalletProviderName,
}
