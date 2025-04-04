use sea_orm_migration::prelude::*;

use crate::m20240319_105859_typed_credential_schema::SCHEMA_ID_IN_ORGANISATION_INDEX;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
