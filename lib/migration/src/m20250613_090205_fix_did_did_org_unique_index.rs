use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::Did;
use crate::m20240116_110014_unique_did_in_organisation::UNIQUE_DID_DID_IN_ORGANISATION_INDEX;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(UNIQUE_DID_DID_IN_ORGANISATION_INDEX)
                    .table(Did::Table)
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        match manager.get_database_backend() {
            DbBackend::Sqlite => {
                let create_unique_index_did = format!(
                    "CREATE UNIQUE INDEX `{UNIQUE_DID_DID_IN_ORGANISATION_INDEX}` ON did(`did`, COALESCE(organisation_id, 'no_organisation'));"
                );
                db.execute_unprepared(&create_unique_index_did).await?;
            }
            _ => {
                let add_generated_column_org_id = "ALTER TABLE did ADD COLUMN organisation_id_materialized VARCHAR(50) AS (COALESCE(TRIM(organisation_id), 'no_organisation')) PERSISTENT;".to_string();
                db.execute_unprepared(&add_generated_column_org_id).await?;
                let create_unique_index_did = format!(
                    "CREATE UNIQUE INDEX `{UNIQUE_DID_DID_IN_ORGANISATION_INDEX}` ON did(`did`, `organisation_id_materialized`);"
                );
                db.execute_unprepared(&create_unique_index_did).await?;
            }
        }
        Ok(())
    }
}
