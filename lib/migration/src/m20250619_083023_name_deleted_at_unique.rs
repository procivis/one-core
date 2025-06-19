use sea_orm::{DatabaseBackend, ExecResult};
use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{CredentialSchema, Did, Key, Organisation, ProofSchema};
use crate::m20240115_093859_unique_did_name_and_key_name_in_org::{
    UNIQUE_DID_NAME_IN_ORGANISATION_INDEX, UNIQUE_KEY_NAME_IN_ORGANISATION_INDEX,
};
use crate::m20240129_112026_add_unique_index_on_credential_schema_name_organisation_deleted_at::UNIQUE_INDEX_CREDENTIAL_SCHEMA_ORGANISATION_ID_NAME_DELETED_AT;
use crate::m20240129_115447_add_unique_index_on_proof_schema_name_organisation_deleted_at::UNIQUE_INDEX_PROOF_SCHEMA_ORGANISATION_ID_NAME_DELETED_AT;
use crate::m20250429_142011_add_identifier::Identifier;
use crate::m20250502_075301_did_identifier::UNIQUE_IDENTIFIER_NAME_IN_ORGANISATION_INDEX;

// newly created unique indexes
const UNIQUE_KEY_NAME_ORGANISATION_DELETED_AT_INDEX: &str =
    "index_Key_Name-OrganisationId-DeletedAt_Unique";
const UNIQUE_DID_NAME_ORGANISATION_DELETED_AT_INDEX: &str =
    "index_Did_Name-OrganisationId-DeletedAt_Unique";
const UNIQUE_IDENTIFIER_NAME_ORGANISATION_DELETED_AT_INDEX: &str =
    "index_Identifier_Name-OrganisationId-DeletedAt_Unique";
const UNIQUE_CREDENTIAL_SCHEMA_NAME_ORGANISATION_DELETED_AT_INDEX: &str =
    "index_CredentialSchema_Name-OrganisationId-DeletedAt_Unique";
const UNIQUE_PROOF_SCHEMA_NAME_ORGANISATION_DELETED_AT_INDEX: &str =
    "index_ProofSchema_Name-OrganisationId-DeletedAt_Unique";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        // remove old indexes
        drop_old_unique_index(UNIQUE_KEY_NAME_IN_ORGANISATION_INDEX, Key::Table, manager).await?;
        drop_old_unique_index(UNIQUE_DID_NAME_IN_ORGANISATION_INDEX, Did::Table, manager).await?;

        // wrongly removed of sqlite in m20250513_075017_rename_identifier_status_to_state
        if backend != DatabaseBackend::Sqlite {
            drop_old_unique_index(
                UNIQUE_IDENTIFIER_NAME_IN_ORGANISATION_INDEX,
                Identifier::Table,
                manager,
            )
            .await?;
        }

        drop_old_unique_index(
            UNIQUE_INDEX_CREDENTIAL_SCHEMA_ORGANISATION_ID_NAME_DELETED_AT,
            CredentialSchema::Table,
            manager,
        )
        .await?;

        // Maria-DB complains: Cannot drop index: needed in a foreign key constraint
        // so temporarily removing the foreign key
        let proof_schema_organisation_foreign_key = Alias::new("fk-ProofSchema-OrganisationId");
        if backend == DatabaseBackend::MySql {
            manager
                .alter_table(
                    Table::alter()
                        .table(ProofSchema::Table)
                        .drop_foreign_key(proof_schema_organisation_foreign_key.to_owned())
                        .to_owned(),
                )
                .await?;
        }
        drop_old_unique_index(
            UNIQUE_INDEX_PROOF_SCHEMA_ORGANISATION_ID_NAME_DELETED_AT,
            ProofSchema::Table,
            manager,
        )
        .await?;
        if backend == DatabaseBackend::MySql {
            manager
                .alter_table(
                    Table::alter()
                        .table(ProofSchema::Table)
                        .add_foreign_key(
                            ForeignKey::create()
                                .name(proof_schema_organisation_foreign_key.to_string())
                                .from_tbl(ProofSchema::Table)
                                .from_col(ProofSchema::OrganisationId)
                                .to_tbl(Organisation::Table)
                                .to_col(Organisation::Id)
                                .get_foreign_key(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        // generate deleted_at_materialized column where needed
        match backend {
            DatabaseBackend::MySql => {
                add_deleted_at_materialized_column(Key::Table, manager).await?;
                add_deleted_at_materialized_column(Did::Table, manager).await?;
                add_deleted_at_materialized_column(Identifier::Table, manager).await?;
                // credential_schema table already has the materialized column since m20241224_08000_fix_index_for_credential_schema
                add_deleted_at_materialized_column(ProofSchema::Table, manager).await?;
            }
            _ => {
                // not necessary for sqlite
            }
        }

        // create new indexes
        add_unique_index_with_deleted_at_materialized_dependency(
            UNIQUE_KEY_NAME_ORGANISATION_DELETED_AT_INDEX,
            Key::Table,
            (Key::Name, Key::OrganisationId),
            manager,
        )
        .await?;
        add_unique_index_with_deleted_at_materialized_dependency(
            UNIQUE_DID_NAME_ORGANISATION_DELETED_AT_INDEX,
            Did::Table,
            (Did::Name, Did::OrganisationId),
            manager,
        )
        .await?;
        add_unique_index_with_deleted_at_materialized_dependency(
            UNIQUE_IDENTIFIER_NAME_ORGANISATION_DELETED_AT_INDEX,
            Identifier::Table,
            (Identifier::Name, Identifier::OrganisationId),
            manager,
        )
        .await?;
        add_unique_index_with_deleted_at_materialized_dependency(
            UNIQUE_CREDENTIAL_SCHEMA_NAME_ORGANISATION_DELETED_AT_INDEX,
            CredentialSchema::Table,
            (CredentialSchema::Name, CredentialSchema::OrganisationId),
            manager,
        )
        .await?;
        add_unique_index_with_deleted_at_materialized_dependency(
            UNIQUE_PROOF_SCHEMA_NAME_ORGANISATION_DELETED_AT_INDEX,
            ProofSchema::Table,
            (ProofSchema::Name, ProofSchema::OrganisationId),
            manager,
        )
        .await?;

        Ok(())
    }
}

async fn drop_old_unique_index(
    index_name: &str,
    table: impl IntoTableRef,
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    manager
        .drop_index(Index::drop().name(index_name).table(table).to_owned())
        .await
}

async fn add_deleted_at_materialized_column(
    table: impl IntoIden,
    manager: &SchemaManager<'_>,
) -> Result<ExecResult, DbErr> {
    let table = table.into_iden().to_string();
    let query = format!(
        "ALTER TABLE `{table}` ADD COLUMN `deleted_at_materialized` VARCHAR(50) AS (COALESCE(`deleted_at`, 'not_deleted')) PERSISTENT;",
    );
    manager.get_connection().execute_unprepared(&query).await
}

async fn add_unique_index_with_deleted_at_materialized_dependency(
    index_name: &str,
    table: impl IntoIden,
    other_colums: impl IdenList,
    manager: &SchemaManager<'_>,
) -> Result<ExecResult, DbErr> {
    let table = table.into_iden().to_string();
    let other_columns = other_colums
        .into_iter()
        .map(|column| format!("`{}`", column.to_string()))
        .collect::<Vec<_>>()
        .join(",");

    let query = match manager.get_database_backend() {
        DatabaseBackend::MySql => {
            format!(
                "CREATE UNIQUE INDEX `{index_name}` ON `{table}`({other_columns},`deleted_at_materialized`);",
            )
        }
        DatabaseBackend::Sqlite => {
            format!(
                "CREATE UNIQUE INDEX `{index_name}` ON `{table}`({other_columns},COALESCE(deleted_at, 'not_deleted'));",
            )
        }
        backend => unimplemented!("Not implemented for: {backend:?}"),
    };

    manager.get_connection().execute_unprepared(&query).await
}
