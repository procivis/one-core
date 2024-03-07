use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ProofInputClaimSchema::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(ProofInputClaimSchema::Required)
                            .boolean()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ProofInputClaimSchema::Table)
                    .drop_column(ProofInputClaimSchema::Required)
                    .to_owned(),
            )
            .await
    }
}

#[allow(dead_code)]
#[derive(DeriveIden)]
pub enum ProofInputClaimSchema {
    Table,
    ClaimSchemaId,
    ProofInputSchemaId,
    Order,
    Required,
}
