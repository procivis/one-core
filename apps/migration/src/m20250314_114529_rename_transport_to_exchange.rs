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
                    .rename_column(Credential::Transport, Credential::Exchange)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
pub enum Credential {
    Table,
    Transport,
    Exchange,
}
