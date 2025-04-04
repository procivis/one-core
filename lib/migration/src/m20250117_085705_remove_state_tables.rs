use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(CredentialState::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(ProofState::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum CredentialState {
    Table,
}

#[derive(DeriveIden)]
pub enum ProofState {
    Table,
}
