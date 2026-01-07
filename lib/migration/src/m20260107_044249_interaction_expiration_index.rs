use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::m20260106_095023_interaction_expires_at::Interaction;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Postgres {
            return Ok(());
        }

        manager
            .create_index(
                Index::create()
                    .name("index-Interaction-ExpiresAt")
                    .table(Interaction::Table)
                    .col(Interaction::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
