use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

use crate::m20240920_115859_import_url::ProofSchema;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres | DatabaseBackend::Sqlite => {}
            DatabaseBackend::MySql => {
                // correct type
                manager
                    .alter_table(
                        Table::alter()
                            .table(ProofSchema::Table)
                            .modify_column(
                                ColumnDef::new(ProofSchema::ImportedSourceUrl).text().null(),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
        };

        Ok(())
    }
}
