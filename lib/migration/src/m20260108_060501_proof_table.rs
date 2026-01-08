use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

use crate::m20250624_093010_rename_exchange_to_protocol::Proof;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres | DatabaseBackend::Sqlite => {}
            DatabaseBackend::MySql => {
                // remove default value
                manager
                    .alter_table(
                        Table::alter()
                            .table(Proof::Table)
                            .modify_column(ColumnDef::new(Proof::Protocol).string().not_null())
                            .to_owned(),
                    )
                    .await?;
            }
        };

        Ok(())
    }
}
