use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::History;

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX_CREDENTIAL_STATE_EXPIRES_AT: &str = "index-Credential-State-ExpiresAt";
const INDEX_HISTORY_ENTITY_TYPE_ACTION: &str = "index-History-EntityType-Action";

// motivation: ONE-11287
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name(INDEX_CREDENTIAL_STATE_EXPIRES_AT)
                    .table(Credential::Table)
                    .col(Credential::State)
                    .col(Credential::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(INDEX_HISTORY_ENTITY_TYPE_ACTION)
                    .table(History::Table)
                    .col(History::EntityType)
                    .col(History::Action)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Credential {
    Table,
    State,
    ExpiresAt,
}
