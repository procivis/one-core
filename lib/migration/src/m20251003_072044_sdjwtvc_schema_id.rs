use sea_orm::{DatabaseBackend, FromQueryResult};
use sea_orm_migration::prelude::*;
use url::Url;

use crate::m20240110_000001_initial::CredentialSchema;
use crate::m20240319_105859_typed_credential_schema::CredentialSchema as CredentialSchemaWithSchemaId;
use crate::m20241224_08000_fix_index_for_credential_schema::UNIQUE_INDEX_CREDENTIAL_SCHEMA_ORGANISATION_TYPE_ID_DELETED_AT_UNIQUE;
use crate::m20250220_080800_add_external_credential_schema_flag::CredentialSchema as CredentialSchemaWithExternalFlag;

#[derive(DeriveMigrationName)]
pub struct Migration;

pub const UNIQUE_INDEX_CREDENTIAL_SCHEMA_ORGANISATION_TYPE_ID_EXTERNAL_DELETED_AT_UNIQUE: &str =
    "index-SchemaId-Organisation-SchemaType-External-DeletedAt_Unique";

#[derive(Debug, FromQueryResult)]
pub struct SchemaEntry {
    id: String,
    schema_id: String,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();
        match backend {
            DatabaseBackend::Postgres => {
                // PostgreSQL support to be implemented
                return Ok(());
            }
            DatabaseBackend::MySql => {
                let q1 = format!(
                    "CREATE UNIQUE INDEX `{UNIQUE_INDEX_CREDENTIAL_SCHEMA_ORGANISATION_TYPE_ID_EXTERNAL_DELETED_AT_UNIQUE}` ON credential_schema(`organisation_id`,`schema_id`,`schema_type`,`external_schema`,`deleted_at_materialized`);"
                );
                db.execute_unprepared(&q1).await?;

                let q2 = format!(
                    "DROP INDEX `{UNIQUE_INDEX_CREDENTIAL_SCHEMA_ORGANISATION_TYPE_ID_DELETED_AT_UNIQUE}` ON credential_schema"
                );
                db.execute_unprepared(&q2).await?;
            }
            DatabaseBackend::Sqlite => {
                let q1 = format!(
                    "CREATE UNIQUE INDEX `{UNIQUE_INDEX_CREDENTIAL_SCHEMA_ORGANISATION_TYPE_ID_EXTERNAL_DELETED_AT_UNIQUE}` ON credential_schema(`organisation_id`,`schema_id`, `schema_type`, `external_schema`, COALESCE(deleted_at, 'not_deleted'));"
                );
                db.execute_unprepared(&q1).await?;

                let q2 = format!(
                    "DROP INDEX `{UNIQUE_INDEX_CREDENTIAL_SCHEMA_ORGANISATION_TYPE_ID_DELETED_AT_UNIQUE}`"
                );
                db.execute_unprepared(&q2).await?;
            }
        };

        let schemas = SchemaEntry::find_by_statement(
            backend.build(
                Query::select()
                    .column(CredentialSchema::Id)
                    .column(CredentialSchemaWithSchemaId::SchemaId)
                    .from(CredentialSchema::Table)
                    .cond_where(Expr::col(CredentialSchema::Format).like("SD_JWT_VC%"))
                    .cond_where(
                        Expr::col(CredentialSchemaWithExternalFlag::ExternalSchema).eq(false),
                    ),
            ),
        )
        .all(db)
        .await?;

        for entry in schemas {
            let Some(url) = Url::parse(&entry.schema_id).ok() else {
                continue;
            };

            let Some(path_segments) = url.path_segments() else {
                continue;
            };

            // {core_url}/ssi/vct/v1/:organisation_id/:schema_id
            let path_segments: Vec<&str> = path_segments.collect();
            let ["ssi", "vct", "v1", _organisation_id, schema_id] = path_segments[..] else {
                continue;
            };

            db.execute(
                backend.build(
                    Query::update()
                        .table(CredentialSchema::Table)
                        .value(CredentialSchemaWithSchemaId::SchemaId, schema_id)
                        .and_where(Expr::col(CredentialSchema::Id).eq(entry.id)),
                ),
            )
            .await?;
        }

        Ok(())
    }
}
