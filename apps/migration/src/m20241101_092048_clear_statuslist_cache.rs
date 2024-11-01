use sea_orm_migration::prelude::*;

use crate::m20240726_084216_rename_jsonldcontextprovider_to_cacheprovider::{
    RemoteEntityCache, RemoteEntityType,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // nothing to do
        Ok(())
    }
}
