use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::CredentialSchema;
use crate::m20240116_153515_make_name_indexes_unique::UNIQUE_CREDENTIAL_SCHEMA_NAME_IN_ORGANISATION_INDEX;

pub const UNIQUE_INDEX_CREDENTIAL_SCHEMA_ORGANISATION_ID_NAME_DELETED_AT: &str =
    "index-CredentialSchema-OrganisationId-Name-DeletedAt_Unique";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .unique()
                    .name(UNIQUE_INDEX_CREDENTIAL_SCHEMA_ORGANISATION_ID_NAME_DELETED_AT)
                    .table(CredentialSchema::Table)
                    .col(CredentialSchema::OrganisationId)
                    .col(CredentialSchema::Name)
                    .col(CredentialSchema::DeletedAt)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(UNIQUE_CREDENTIAL_SCHEMA_NAME_IN_ORGANISATION_INDEX)
                    .table(CredentialSchema::Table)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .unique()
                    .name(UNIQUE_CREDENTIAL_SCHEMA_NAME_IN_ORGANISATION_INDEX)
                    .table(CredentialSchema::Table)
                    .col(CredentialSchema::OrganisationId)
                    .col(CredentialSchema::Name)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(UNIQUE_INDEX_CREDENTIAL_SCHEMA_ORGANISATION_ID_NAME_DELETED_AT)
                    .table(CredentialSchema::Table)
                    .to_owned(),
            )
            .await
    }
}
