use crate::m20230530_000001_initial::Proof;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

impl Migration {
    fn transport_column() -> Alias {
        Alias::new("transport")
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Proof::Table)
                    .add_column(
                        ColumnDef::new(Migration::transport_column())
                            .string()
                            .not_null()
                            .default("PROCIVIS_TEMPORARY"),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Proof::Table)
                    .drop_column(Migration::transport_column())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
