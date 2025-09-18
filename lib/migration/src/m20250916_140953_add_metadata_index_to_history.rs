use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .create_index(
                Index::create()
                    .table(History::Table)
                    .name("index-History-Metadata")
                    .col(History::Metadata)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum History {
    Table,
    Metadata,
}
