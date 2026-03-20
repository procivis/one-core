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
                    .table(TrustCollection::Table)
                    .add_column(text_null(TrustCollection::RemoteTrustCollectionUrl))
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum TrustCollection {
    Table,
    RemoteTrustCollectionUrl,
}
