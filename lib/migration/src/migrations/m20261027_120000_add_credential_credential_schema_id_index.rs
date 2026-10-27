use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::Credential;

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX_CREDENTIAL_CREDENTIAL_SCHEMA_ID: &str = "index-Credential-CredentialSchemaId";

// Adds missing FK child column index, as Postgres does not automatically create one.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name(INDEX_CREDENTIAL_CREDENTIAL_SCHEMA_ID)
                    .table(Credential::Table)
                    .col(Credential::CredentialSchemaId)
                    .to_owned(),
            )
            .await
    }
}
