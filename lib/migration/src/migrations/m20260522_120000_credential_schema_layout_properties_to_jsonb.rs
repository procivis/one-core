use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{
    boolean, boolean_null, integer_null, json_binary_null, string, string_len_null, string_null,
};

use crate::datatype::{timestamp, timestamp_null, uuid_char};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.supported_db_type() {
            SupportedDbType::MySql => {
                // JSONB type is resolved into JSON in this case, thus we don't have to execute migration there
                Ok(())
            }
            SupportedDbType::Sqlite => alter_credential_schema_sqlite(manager).await,
            SupportedDbType::Postgres => {
                // json_binary_null(CredentialSchema::LayoutProperties).using("layout_properties::JSONB") creates strange SQL:
                //    ALTER TABLE "credential_schema" ALTER COLUMN "layout_properties" TYPE jsonb, ALTER COLUMN "layout_properties" DROP NOT NULL USING 'layout_properties::JSONB'
                // so I used raw version
                let db = manager.get_connection();
                db.execute_unprepared(
                    r#"ALTER TABLE "credential_schema"
                       ALTER COLUMN "layout_properties" TYPE JSONB
                       USING "layout_properties"::JSONB"#,
                )
                .await
                .map(|_| ())
            }
        }
    }
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
                .col(json_binary_null(CredentialSchemaNew::LayoutProperties))
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
        CredentialSchemaNew::BatchSize,
        CredentialSchemaNew::AllowRevocation,
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

    db.execute_unprepared(&format!(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS "{INDEX_CREDENTIAL_SCHEMA_NAME_ORGANISATION_ID_DELETED_AT_UNIQUE}"
        ON "credential_schema" (
            "name",
            "organisation_id",
            COALESCE("deleted_at", 'not_deleted')
        );
        "#,
    ))
    .await?;

    db.execute_unprepared(&format!(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS "{INDEX_CREDENTIAL_SCHEMA_SCHEMA_ID_ORG_DELETED_PARTIAL}"
        ON "credential_schema" (
            "organisation_id",
            "schema_id",
            COALESCE("deleted_at", 'not_deleted')
        )
        WHERE "schema_id" IS NOT NULL;
        "#,
    ))
    .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

#[derive(Clone, DeriveIden)]
enum CredentialSchema {
    Table,
    CreatedDate,
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
enum Organisation {
    Table,
    Id,
}

const FK_CREDENTIAL_SCHEMA_ORGANISATION: &str = "fk-CredentialSchema-OrganisationId";
const INDEX_CREDENTIAL_SCHEMA_CREATED_DATE: &str = "index-CredentialSchema-CreatedDate";
const INDEX_CREDENTIAL_SCHEMA_SCHEMA_ID_ORG_DELETED_PARTIAL: &str =
    "index-Organisation-SchemaId-DeletedAt-Partial_Unique";
const INDEX_CREDENTIAL_SCHEMA_NAME_ORGANISATION_ID_DELETED_AT_UNIQUE: &str =
    "index_CredentialSchema_Name-OrganisationId-DeletedAt_Unique";
