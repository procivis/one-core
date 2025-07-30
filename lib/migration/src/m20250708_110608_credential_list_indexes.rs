use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::Credential;
use crate::m20240118_070610_credential_add_role::CredentialNew as CredentialWithRole;
use crate::m20241212_08000_migrate_credential_state::Credential as CredentialWithState;

#[derive(DeriveMigrationName)]
pub struct Migration;

pub const CREDENTIAL_ROLE_INDEX: &str = "index-Credential-Role";
pub const CREDENTIAL_STATE_INDEX: &str = "index-Credential-State";
pub const CREDENTIAL_DELETED_AT_INDEX: &str = "index-Credential-DeletedAt";
pub const CREDENTIAL_SUSPEND_END_DATE_INDEX: &str = "index-Credential-SuspendEndDate";

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
                    .name(CREDENTIAL_ROLE_INDEX)
                    .table(Credential::Table)
                    .col(CredentialWithRole::Role)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(CREDENTIAL_DELETED_AT_INDEX)
                    .table(Credential::Table)
                    .col(Credential::DeletedAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(CREDENTIAL_STATE_INDEX)
                    .table(Credential::Table)
                    .col(CredentialWithState::State)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(CREDENTIAL_SUSPEND_END_DATE_INDEX)
                    .table(Credential::Table)
                    .col(CredentialWithState::SuspendEndDate)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
