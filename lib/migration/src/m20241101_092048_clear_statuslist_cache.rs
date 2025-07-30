use sea_orm_migration::prelude::*;

use crate::m20240726_084216_rename_jsonldcontextprovider_to_cacheprovider::{
    RemoteEntityCache, RemoteEntityType,
};

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
        // Clear cached status lists
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(RemoteEntityCache::Table)
                    .and_where(
                        Expr::col(RemoteEntityCache::Type)
                            .eq(RemoteEntityType::StatusListCredential.as_expr()),
                    )
                    .to_owned(),
            )
            .await
    }
}
