use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(text_null(Credential::WebhookUrl))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Proof::Table)
                    .add_column(text_null(Proof::WebhookUrl))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Credential {
    Table,
    WebhookUrl,
}

#[derive(DeriveIden)]
enum Proof {
    Table,
    WebhookUrl,
}
