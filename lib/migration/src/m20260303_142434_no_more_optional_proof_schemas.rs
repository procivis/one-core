use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::update()
                    .table(ProofInputClaimSchema::Table)
                    .value(ProofInputClaimSchema::Required, true)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum ProofInputClaimSchema {
    Table,
    Required,
}
