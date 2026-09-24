use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{
    boolean, boolean_null, integer_null, json_null, string, string_len_null, string_null,
};

use crate::datatype::{timestamp, timestamp_null, uuid_char};
use crate::index_helper::table_with_indexes;
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_credential_schema_format(manager).await?;
        create_credential_schema_format_claim_schema(manager).await?;
        add_business_key_to_claim_schema(manager).await?;
        alter_credential_schema(manager).await?;
        Ok(())
    }
}

async fn create_credential_schema_format(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(CredentialSchemaFormat::Table)
        .col(uuid_char(CredentialSchemaFormat::Id).primary_key())
        .col(timestamp(CredentialSchemaFormat::CreatedDate, manager))
        .col(timestamp(CredentialSchemaFormat::LastModified, manager))
        .col(uuid_char(CredentialSchemaFormat::CredentialSchemaId))
        .col(string(CredentialSchemaFormat::Format))
        .col(string(CredentialSchemaFormat::SchemaId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CREDENTIAL_SCHEMA_FORMAT_CREDENTIAL_SCHEMA)
                .from_tbl(CredentialSchemaFormat::Table)
                .from_col(CredentialSchemaFormat::CredentialSchemaId)
                .to_tbl(CredentialSchema::Table)
                .to_col(CredentialSchema::Id),
        )
        .to_owned();

    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_CREDENTIAL_SCHEMA_FORMAT_CREDENTIAL_SCHEMA_ID_FORMAT)
            .unique()
            .table(CredentialSchemaFormat::Table)
            .col(CredentialSchemaFormat::CredentialSchemaId)
            .col(CredentialSchemaFormat::Format)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_CREDENTIAL_SCHEMA_FORMAT_CREDENTIAL_SCHEMA_ID_SCHEMA_ID)
            .unique()
            .table(CredentialSchemaFormat::Table)
            .col(CredentialSchemaFormat::CredentialSchemaId)
            .col(CredentialSchemaFormat::SchemaId)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn create_credential_schema_format_claim_schema(
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(CredentialSchemaFormatClaimSchema::Table)
        .col(uuid_char(CredentialSchemaFormatClaimSchema::Id).primary_key())
        .col(timestamp(
            CredentialSchemaFormatClaimSchema::CreatedDate,
            manager,
        ))
        .col(timestamp(
            CredentialSchemaFormatClaimSchema::LastModified,
            manager,
        ))
        .col(uuid_char(
            CredentialSchemaFormatClaimSchema::CredentialSchemaFormatId,
        ))
        .col(uuid_char(CredentialSchemaFormatClaimSchema::ClaimSchemaId))
        .col(string(CredentialSchemaFormatClaimSchema::TechnicalKey))
        .col(string_null(CredentialSchemaFormatClaimSchema::Namespace))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CREDENTIAL_SCHEMA_FORMAT_CLAIM_SCHEMA_FORMAT)
                .from_tbl(CredentialSchemaFormatClaimSchema::Table)
                .from_col(CredentialSchemaFormatClaimSchema::CredentialSchemaFormatId)
                .to_tbl(CredentialSchemaFormat::Table)
                .to_col(CredentialSchemaFormat::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CREDENTIAL_SCHEMA_FORMAT_CLAIM_SCHEMA_CLAIM)
                .from_tbl(CredentialSchemaFormatClaimSchema::Table)
                .from_col(CredentialSchemaFormatClaimSchema::ClaimSchemaId)
                .to_tbl(ClaimSchema::Table)
                .to_col(ClaimSchema::Id),
        )
        .to_owned();

    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_CREDENTIAL_SCHEMA_FORMAT_CLAIM_SCHEMA_FORMAT_CLAIM)
            .unique()
            .table(CredentialSchemaFormatClaimSchema::Table)
            .col(CredentialSchemaFormatClaimSchema::CredentialSchemaFormatId)
            .col(CredentialSchemaFormatClaimSchema::ClaimSchemaId)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn add_business_key_to_claim_schema(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(ClaimSchema::Table)
                .add_column(string_null(ClaimSchema::BusinessKey))
                .to_owned(),
        )
        .await
}

async fn alter_credential_schema(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    match manager.supported_db_type() {
        SupportedDbType::Sqlite => {
            alter_credential_schema_sqlite(manager).await?;
            create_partial_unique_index(manager).await?;
        }
        SupportedDbType::MySql | SupportedDbType::Postgres => {
            alter_credential_schema_mysql_postgres(manager).await?;
            // Create the new index BEFORE dropping the old one: on MariaDB/MySQL the old index
            // covers the (credential_schema.organisation_id → organisation.id) FK, and InnoDB
            // refuses to drop the only covering index for an FK column. The new partial index
            // has `organisation_id` as leading column too, so once it exists the drop succeeds.
            create_partial_unique_index(manager).await?;
            manager
                .drop_index(
                    Index::drop()
                        .name(OLD_INDEX_CREDENTIAL_SCHEMA_SCHEMA_ID_ORG_DELETED)
                        .table(CredentialSchema::Table)
                        .to_owned(),
                )
                .await?;
        }
    }
    Ok(())
}

async fn alter_credential_schema_mysql_postgres(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(CredentialSchema::Table)
                .add_column(integer_null(CredentialSchema::BatchSize))
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(CredentialSchema::Table)
                .add_column(boolean_null(CredentialSchema::AllowRevocation))
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(CredentialSchema::Table)
                .modify_column(ColumnDef::new(CredentialSchema::Format).string().null())
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(CredentialSchema::Table)
                .modify_column(ColumnDef::new(CredentialSchema::SchemaId).string().null())
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn alter_credential_schema_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    manager
        .create_table(
            Table::create()
                .table(CredentialSchemaNew::Table)
                .col(uuid_char(CredentialSchemaNew::Id).primary_key())
                .col(timestamp(CredentialSchemaNew::CreatedDate, manager))
                .col(timestamp(CredentialSchemaNew::LastModified, manager))
                .col(timestamp_null(CredentialSchemaNew::DeletedAt, manager))
                .col(string(CredentialSchemaNew::Name))
                .col(string_null(CredentialSchemaNew::Format))
                .col(string_null(CredentialSchemaNew::RevocationMethod))
                .col(string_null(CredentialSchemaNew::SchemaId))
                .col(string(CredentialSchemaNew::LayoutType))
                .col(json_null(CredentialSchemaNew::LayoutProperties))
                .col(string(CredentialSchemaNew::ImportedSourceUrl))
                .col(boolean(CredentialSchemaNew::AllowSuspension))
                .col(boolean(
                    CredentialSchemaNew::RequiresWalletInstanceAttestation,
                ))
                .col(string_null(CredentialSchemaNew::KeyStorageSecurity))
                .col(string_null(CredentialSchemaNew::TransactionCodeType))
                .col(integer_null(CredentialSchemaNew::TransactionCodeLength))
                .col(string_len_null(
                    CredentialSchemaNew::TransactionCodeDescription,
                    300,
                ))
                .col(uuid_char(CredentialSchemaNew::OrganisationId))
                .col(integer_null(CredentialSchemaNew::BatchSize))
                .col(boolean_null(CredentialSchemaNew::AllowRevocation))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_SCHEMA_ORGANISATION)
                        .from_tbl(CredentialSchemaNew::Table)
                        .from_col(CredentialSchemaNew::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        CredentialSchemaNew::Id,
        CredentialSchemaNew::CreatedDate,
        CredentialSchemaNew::LastModified,
        CredentialSchemaNew::DeletedAt,
        CredentialSchemaNew::Name,
        CredentialSchemaNew::Format,
        CredentialSchemaNew::RevocationMethod,
        CredentialSchemaNew::SchemaId,
        CredentialSchemaNew::LayoutType,
        CredentialSchemaNew::LayoutProperties,
        CredentialSchemaNew::ImportedSourceUrl,
        CredentialSchemaNew::AllowSuspension,
        CredentialSchemaNew::RequiresWalletInstanceAttestation,
        CredentialSchemaNew::KeyStorageSecurity,
        CredentialSchemaNew::TransactionCodeType,
        CredentialSchemaNew::TransactionCodeLength,
        CredentialSchemaNew::TransactionCodeDescription,
        CredentialSchemaNew::OrganisationId,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(CredentialSchemaNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(CredentialSchema::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(CredentialSchema::Table).to_owned())
        .await?;
    manager
        .rename_table(
            Table::rename()
                .table(CredentialSchemaNew::Table, CredentialSchema::Table)
                .to_owned(),
        )
        .await?;

    // The old (schema_id, organisation_id, deleted_at) unique index is intentionally NOT
    // recreated here — create_partial_unique_index() builds its replacement.
    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name(INDEX_CREDENTIAL_SCHEMA_CREATED_DATE)
                .table(CredentialSchema::Table)
                .col(CredentialSchema::CreatedDate)
                .to_owned(),
        )
        .await?;
    db.execute_unprepared(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS "index_CredentialSchema_Name-OrganisationId-DeletedAt_Unique"
        ON "credential_schema" (
            "name",
            "organisation_id",
            COALESCE("deleted_at", 'not_deleted')
        );
        "#,
    )
    .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

async fn create_partial_unique_index(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let name = INDEX_CREDENTIAL_SCHEMA_SCHEMA_ID_ORG_DELETED_PARTIAL;
    match manager.supported_db_type() {
        SupportedDbType::Postgres => {
            db.execute_unprepared(&format!(
                r#"
                CREATE UNIQUE INDEX IF NOT EXISTS "{name}"
                ON "credential_schema" ("organisation_id", "schema_id", "deleted_at")
                NULLS NOT DISTINCT
                WHERE "schema_id" IS NOT NULL;
                "#
            ))
            .await?;
        }
        SupportedDbType::Sqlite => {
            db.execute_unprepared(&format!(
                r#"
                CREATE UNIQUE INDEX IF NOT EXISTS "{name}"
                ON "credential_schema" (
                    "organisation_id",
                    "schema_id",
                    COALESCE("deleted_at", 'not_deleted')
                )
                WHERE "schema_id" IS NOT NULL;
                "#
            ))
            .await?;
        }
        SupportedDbType::MySql => {
            db.execute_unprepared(&format!(
                r#"
                CREATE UNIQUE INDEX `{name}`
                ON `credential_schema` (`organisation_id`, `schema_id`, `deleted_at_materialized`);
                "#
            ))
            .await?;
        }
    }
    Ok(())
}

#[derive(DeriveIden)]
enum CredentialSchema {
    Table,
    Id,
    CreatedDate,
    Format,
    SchemaId,
    BatchSize,
    AllowRevocation,
}

#[derive(DeriveIden)]
enum Organisation {
    Table,
    Id,
}

#[derive(Clone, DeriveIden)]
enum CredentialSchemaNew {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeletedAt,
    Name,
    Format,
    RevocationMethod,
    SchemaId,
    LayoutType,
    LayoutProperties,
    ImportedSourceUrl,
    AllowSuspension,
    RequiresWalletInstanceAttestation,
    KeyStorageSecurity,
    TransactionCodeType,
    TransactionCodeLength,
    TransactionCodeDescription,
    OrganisationId,
    BatchSize,
    AllowRevocation,
}

#[derive(DeriveIden)]
pub enum ClaimSchema {
    Table,
    Id,
    BusinessKey,
}

#[derive(DeriveIden)]
pub enum CredentialSchemaFormat {
    Table,
    Id,
    CreatedDate,
    LastModified,
    CredentialSchemaId,
    Format,
    SchemaId,
}

#[derive(DeriveIden)]
pub enum CredentialSchemaFormatClaimSchema {
    Table,
    Id,
    CreatedDate,
    LastModified,
    CredentialSchemaFormatId,
    ClaimSchemaId,
    TechnicalKey,
    Namespace,
}

const FK_CREDENTIAL_SCHEMA_FORMAT_CREDENTIAL_SCHEMA: &str =
    "fk-CredentialSchemaFormat-CredentialSchemaId";
const FK_CREDENTIAL_SCHEMA_FORMAT_CLAIM_SCHEMA_FORMAT: &str =
    "fk-CredentialSchemaFormatClaimSchema-CredentialSchemaFormatId";
const FK_CREDENTIAL_SCHEMA_FORMAT_CLAIM_SCHEMA_CLAIM: &str =
    "fk-CredentialSchemaFormatClaimSchema-ClaimSchemaId";

const INDEX_UNIQUE_CREDENTIAL_SCHEMA_FORMAT_CREDENTIAL_SCHEMA_ID_FORMAT: &str =
    "index-CredentialSchemaFormat-CredentialSchemaId-Format_Unique";
const INDEX_UNIQUE_CREDENTIAL_SCHEMA_FORMAT_CREDENTIAL_SCHEMA_ID_SCHEMA_ID: &str =
    "index-CredentialSchemaFormat-CredentialSchemaId-SchemaId_Unique";
const INDEX_UNIQUE_CREDENTIAL_SCHEMA_FORMAT_CLAIM_SCHEMA_FORMAT_CLAIM: &str =
    "index-FormatClaimSchema-FormatId-ClaimSchemaId_Unique";

const OLD_INDEX_CREDENTIAL_SCHEMA_SCHEMA_ID_ORG_DELETED: &str =
    "index-Organisation-SchemaId-DeletedAt_Unique";
const INDEX_CREDENTIAL_SCHEMA_SCHEMA_ID_ORG_DELETED_PARTIAL: &str =
    "index-Organisation-SchemaId-DeletedAt-Partial_Unique";
const INDEX_CREDENTIAL_SCHEMA_CREATED_DATE: &str = "index-CredentialSchema-CreatedDate";

// Matches the constant in the initial migration so the SQLite-rewritten table's FK is
// identical to the original.
const FK_CREDENTIAL_SCHEMA_ORGANISATION: &str = "fk-CredentialSchema-OrganisationId";
