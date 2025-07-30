use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::MySql {
            manager
                .alter_table(
                    Table::alter()
                        .table(Credential::Table)
                        .modify_column(ColumnDef::new(Credential::RedirectUri).string_len(1000))
                        .to_owned(),
                )
                .await?;
            manager
                .alter_table(
                    Table::alter()
                        .table(Proof::Table)
                        .modify_column(ColumnDef::new(Proof::RedirectUri).string_len(1000))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

#[derive(Iden)]
pub enum Credential {
    Table,
    RedirectUri,
}

#[derive(Iden)]
pub enum Proof {
    Table,
    RedirectUri,
}
