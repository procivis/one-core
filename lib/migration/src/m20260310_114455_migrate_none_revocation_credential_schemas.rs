use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        crate::m20260127_144700_nullable_credential_schema_revocation_method::migrate_columns(
            manager,
        )
        .await
    }
}
