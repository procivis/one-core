use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240514_070446_add_trust_model::TrustEntity;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        manager
            .alter_table(
                Table::alter()
                    .table(TrustEntity::Table)
                    .drop_column(TrustEntity::Logo)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(TrustEntity::Table)
                    .add_column(ColumnDef::new(TrustEntity::Logo).large_blob(manager))
                    .to_owned(),
            )
            .await
    }
}
