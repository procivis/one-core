use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::{Did, INDEX_UNIQUE_DID_DID_ORGANISATION};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const NEW_INDEX_DID_DID_ORGANISATION_DELETED_AT: &str =
    "index-Did-Did-OrganisationId-DeletedAt-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create the new (did, organisation_id, deleted_at) unique index before dropping
        // the old (did, organisation_id) one, to avoid any FK covering-index edge case.

        // add_nullable_unique_idx only supports one nullable column, so index is created manually
        // Also, the materialized columns already exist.
        match manager.supported_db_type() {
            SupportedDbType::Postgres => {
                manager
                    .create_index(
                        Index::create()
                            .if_not_exists()
                            .name(NEW_INDEX_DID_DID_ORGANISATION_DELETED_AT)
                            .table(Did::Table)
                            .unique()
                            .nulls_not_distinct()
                            .col(Did::Did)
                            .col(Did::OrganisationId)
                            .col(Did::DeletedAt)
                            .to_owned(),
                    )
                    .await?;
            }
            SupportedDbType::Sqlite => {
                manager
                    .get_connection()
                    .execute_unprepared(&format!(
                        r#"
                        CREATE UNIQUE INDEX IF NOT EXISTS "{NEW_INDEX_DID_DID_ORGANISATION_DELETED_AT}"
                        ON "did" (
                            "did",
                            COALESCE("organisation_id", 'no_organisation'),
                            COALESCE("deleted_at", 'not_deleted')
                        );
                        "#
                    ))
                    .await?;
            }
            SupportedDbType::MySql => {
                manager
                    .get_connection()
                    .execute_unprepared(&format!(
                        "CREATE UNIQUE INDEX `{NEW_INDEX_DID_DID_ORGANISATION_DELETED_AT}` \
                         ON `did`(`did`, `organisation_id_materialized`, `deleted_at_materialized`);"
                    ))
                    .await?;
            }
        }

        manager
            .drop_index(
                Index::drop()
                    .name(INDEX_UNIQUE_DID_DID_ORGANISATION)
                    .table(Did::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
