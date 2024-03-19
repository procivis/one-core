use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ProofSchema::Table)
                    .add_column(
                        ColumnDef::new(ProofSchema::ValidityConstraint)
                            .big_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ProofSchema::Table)
                    .drop_column(ProofSchema::ValidityConstraint)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum ProofSchema {
    Table,
    ValidityConstraint,
}
