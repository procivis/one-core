use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

use crate::m20250317_133346_add_org_name::Organisation;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres | DatabaseBackend::Sqlite => {}
            DatabaseBackend::MySql => {
                // remove default values
                manager
                    .alter_table(
                        Table::alter()
                            .table(Organisation::Table)
                            .modify_column(ColumnDef::new(Organisation::Name).text().not_null())
                            .to_owned(),
                    )
                    .await?;
            }
        };

        Ok(())
    }
}
