use sea_orm_migration::prelude::*;

use crate::m20240514_070446_add_trust_model::TrustEntity;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            sea_orm::DatabaseBackend::Postgres => return Ok(()),
            sea_orm::DatabaseBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(TrustEntity::Table)
                            .modify_column(ColumnDef::new(TrustEntity::EntityId).text().not_null())
                            .take(),
                    )
                    .await?;
            }
            sea_orm::DatabaseBackend::Sqlite => {}
        }
        Ok(())
    }
}
