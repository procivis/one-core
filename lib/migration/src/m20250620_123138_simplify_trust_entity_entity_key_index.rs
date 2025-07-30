use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::m20241120_164124_update_trust_anchor_and_entity_tables::TrustEntity;
use crate::m20250611_110354_trust_entity_remove_did_add_org_type_content_entitykey::UNIQUE_ENTITY_KEY_STATE_TRUST_ANCHOR_DEACTIVATED_IN_TRUST_ENTITY;

pub const UNIQUE_ENTITY_KEY_TRUST_ANCHOR_DEACTIVATED_IN_TRUST_ENTITY: &str =
    "idx-TrustEntity-EntityKey-AnchorId-DeactivatedAt-Unique";

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
                    .name(UNIQUE_ENTITY_KEY_STATE_TRUST_ANCHOR_DEACTIVATED_IN_TRUST_ENTITY)
                    .table(TrustEntity::Table)
                    .to_owned(),
            )
            .await?;

        match manager.get_database_backend() {
            DbBackend::Sqlite => create_sqlite_index(manager).await,
            _ => create_index(manager).await,
        }
    }
}

async fn create_index(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let create_unique_index_name = format!(
        "CREATE UNIQUE INDEX `{UNIQUE_ENTITY_KEY_TRUST_ANCHOR_DEACTIVATED_IN_TRUST_ENTITY}` ON trust_entity(`entity_key`, `trust_anchor_id`, `deactivated_at_materialized`);"
    );
    manager
        .get_connection()
        .execute_unprepared(&create_unique_index_name)
        .await?;
    Ok(())
}

async fn create_sqlite_index(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let create_unique_index_name = format!(
        "CREATE UNIQUE INDEX `{UNIQUE_ENTITY_KEY_TRUST_ANCHOR_DEACTIVATED_IN_TRUST_ENTITY}` ON trust_entity(`entity_key`, `trust_anchor_id`, COALESCE(deactivated_at, 'not_deactivated'));"
    );
    manager
        .get_connection()
        .execute_unprepared(&create_unique_index_name)
        .await?;
    Ok(())
}
