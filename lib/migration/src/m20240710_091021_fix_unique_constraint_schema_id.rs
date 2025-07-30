use sea_orm_migration::prelude::*;

use crate::m20240319_105859_typed_credential_schema::SCHEMA_ID_IN_ORGANISATION_INDEX;

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
            .drop_index(
                Index::drop()
                    .name(SCHEMA_ID_IN_ORGANISATION_INDEX)
                    .table(CredentialSchema::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .unique()
                    .name(SCHEMA_ID_IN_ORGANISATION_INDEX)
                    .table(CredentialSchema::Table)
                    .col(CredentialSchema::OrganisationId)
                    .col(CredentialSchema::SchemaId)
                    .col(CredentialSchema::DeletedAt)
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
pub enum CredentialSchema {
    Table,
    SchemaId,
    OrganisationId,
    DeletedAt,
}
