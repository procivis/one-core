use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{Credential, CredentialSchema, Did, Key, Proof, ProofSchema};

#[derive(DeriveMigrationName)]
pub struct Migration;

pub const CREDENTIAL_CREATED_DATE_INDEX: &str = "index-Credential-CreatedDate";
const CREDENTIAL_SCHEMA_CREATED_DATE_INDEX: &str = "index-CredentialSchema-CreatedDate";
const PROOF_CREATED_DATE_INDEX: &str = "index-Proof-CreatedDate";
const PROOF_SCHEMA_CREATED_DATE_INDEX: &str = "index-ProofSchema-CreatedDate";
const DID_CREATED_DATE_INDEX: &str = "index-Did-CreatedDate";
const KEY_CREATED_DATE_INDEX: &str = "index-Key-CreatedDate";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        manager
            .create_index(
                Index::create()
                    .name(CREDENTIAL_CREATED_DATE_INDEX)
                    .table(Credential::Table)
                    .col(Credential::CreatedDate)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(CREDENTIAL_SCHEMA_CREATED_DATE_INDEX)
                    .table(CredentialSchema::Table)
                    .col(CredentialSchema::CreatedDate)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(PROOF_CREATED_DATE_INDEX)
                    .table(Proof::Table)
                    .col(Proof::CreatedDate)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(PROOF_SCHEMA_CREATED_DATE_INDEX)
                    .table(ProofSchema::Table)
                    .col(ProofSchema::CreatedDate)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(DID_CREATED_DATE_INDEX)
                    .table(Did::Table)
                    .col(Did::CreatedDate)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(KEY_CREATED_DATE_INDEX)
                    .table(Key::Table)
                    .col(Key::CreatedDate)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
