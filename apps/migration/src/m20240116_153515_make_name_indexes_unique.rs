use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{
    CredentialSchema, ProofSchema, CREDENTIAL_SCHEMA_NAME_IN_ORGANISATION_INDEX,
    PROOF_SCHEMA_NAME_IN_ORGANISATION_INDEX,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

const UNIQUE_CREDENTIAL_SCHEMA_NAME_IN_ORGANISATION_INDEX: &str =
    "index-CredentialSchema-Name-OrganisationId-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_CREDENTIAL_SCHEMA_NAME_IN_ORGANISATION_INDEX)
                    .unique()
                    .table(CredentialSchema::Table)
                    .col(CredentialSchema::OrganisationId)
                    .col(CredentialSchema::Name)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(CREDENTIAL_SCHEMA_NAME_IN_ORGANISATION_INDEX)
                    .table(CredentialSchema::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(PROOF_SCHEMA_NAME_IN_ORGANISATION_INDEX)
                    .table(ProofSchema::Table)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name(CREDENTIAL_SCHEMA_NAME_IN_ORGANISATION_INDEX)
                    .table(CredentialSchema::Table)
                    .col(CredentialSchema::OrganisationId)
                    .col(CredentialSchema::Name)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(PROOF_SCHEMA_NAME_IN_ORGANISATION_INDEX)
                    .table(ProofSchema::Table)
                    .col(ProofSchema::OrganisationId)
                    .col(ProofSchema::Name)
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
}
