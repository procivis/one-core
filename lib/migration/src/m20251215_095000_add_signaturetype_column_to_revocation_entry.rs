use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(RevocationListEntry::Table)
                    .add_column(string_null(RevocationListEntry::SignatureType))
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden, Clone)]
enum RevocationListEntry {
    Table,
    SignatureType,
}
