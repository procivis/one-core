use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            return Ok(());
        }

        // Drop the old ExpirationDate column
        manager
            .alter_table(
                Table::alter()
                    .table(WalletUnitAttestation::Table)
                    .drop_column(WalletUnitAttestation::ExpirationDate)
                    .to_owned(),
            )
            .await?;

        // Add a new ExpirationDate column with not null constraint
        manager
            .alter_table(
                Table::alter()
                    .table(WalletUnitAttestation::Table)
                    .add_column(
                        ColumnDef::new(WalletUnitAttestation::ExpirationDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(Iden)]
#[allow(clippy::enum_variant_names)]
enum WalletUnitAttestation {
    Table,
    ExpirationDate,
}
