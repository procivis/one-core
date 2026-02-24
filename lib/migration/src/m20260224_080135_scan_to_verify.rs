use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

use crate::deletion::hard_delete_credential_schemas_and_related;
use crate::m20240110_000001_initial::CredentialSchema;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        if backend == DatabaseBackend::Postgres {
            return Ok(());
        }
        hard_delete_credential_schemas_and_related(
            manager,
            Expr::col(CredentialSchema::Format).eq("PHYSICAL_CARD"),
        )
        .await
    }
}
