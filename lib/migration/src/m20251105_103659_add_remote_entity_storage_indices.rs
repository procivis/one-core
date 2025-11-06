use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::m20250630_144901_add_expiry_to_remote_entity_cache::RemoteEntityCache;
use crate::m20250710_065056_cache_clear_by_last_used::NewRemoteEntityCache;

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
                    .name("index-RemoteEntityCache-Key-Unique")
                    .unique()
                    .table(RemoteEntityCache::Table)
                    .col(NewRemoteEntityCache::Key)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("index-RemoteEntityCache-Type-ExpirationDate")
                    .table(RemoteEntityCache::Table)
                    .col(NewRemoteEntityCache::Type)
                    .col(NewRemoteEntityCache::ExpirationDate)
                    .to_owned(),
            )
            .await
    }
}
