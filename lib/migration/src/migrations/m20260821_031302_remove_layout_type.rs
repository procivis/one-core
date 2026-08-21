use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::CredentialSchema;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .drop_column(CredentialSchema::LayoutType)
                    .to_owned(),
            )
            .await
    }
}
