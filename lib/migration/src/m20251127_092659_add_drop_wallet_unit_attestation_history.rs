use sea_orm_migration::prelude::*;

use crate::m20240130_105023_add_history::History;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .exec_stmt(
                Query::delete()
                    .from_table(History::Table)
                    .and_where(Expr::col(History::EntityType).eq("WALLET_UNIT_ATTESTATION"))
                    .to_owned(),
            )
            .await
    }
}
