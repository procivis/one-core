use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .rename_column(Credential::Exchange, Credential::Protocol)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Proof::Table)
                    .rename_column(Proof::Exchange, Proof::Protocol)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum Credential {
    Table,
    Exchange,
    Protocol,
}

#[derive(Iden)]
pub enum Proof {
    Table,
    Exchange,
    Protocol,
}
