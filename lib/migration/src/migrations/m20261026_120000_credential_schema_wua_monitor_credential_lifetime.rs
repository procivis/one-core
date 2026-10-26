use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{
    boolean, integer_null, json_binary_null, string, string_len_null, string_null, text_null,
};

use crate::datatype::{timestamp, timestamp_null, uuid_char};
use crate::migrations::m20260417_150300_initial::Organisation;
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.supported_db_type() == SupportedDbType::Sqlite {
            return sqlite_migration(manager).await;
        }

        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column(
                        boolean(CredentialSchema::WuaMonitorCredentialLifetime).default(false),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(&format!(
                "ALTER TABLE {table} ALTER COLUMN {column} DROP DEFAULT",
                table = CredentialSchema::Table.to_string(),
                column = CredentialSchema::WuaMonitorCredentialLifetime.to_string(),
            ))
            .await?;

        Ok(())
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    manager
        .create_table(
            Table::create()
                .table(CredentialSchemaNew::Table)
                .col(uuid_char(CredentialSchema::Id).primary_key())
                .col(timestamp(CredentialSchema::CreatedDate, manager))
                .col(timestamp(CredentialSchema::LastModified, manager))
                .col(timestamp_null(CredentialSchema::DeletedAt, manager))
                .col(string(CredentialSchema::Name))
                .col(json_binary_null(CredentialSchema::LayoutProperties))
                .col(string(CredentialSchema::ImportedSourceUrl))
                .col(boolean(CredentialSchema::AllowSuspension))
                .col(boolean(CredentialSchema::AllowRevocation))
                .col(boolean(CredentialSchema::RequiresWalletInstanceAttestation))
                .col(string_null(CredentialSchema::KeyStorageSecurity))
                .col(string_null(CredentialSchema::TransactionCodeType))
                .col(integer_null(CredentialSchema::TransactionCodeLength))
                .col(string_len_null(
                    CredentialSchema::TransactionCodeDescription,
                    300,
                ))
                .col(uuid_char(CredentialSchema::OrganisationId))
                .col(integer_null(CredentialSchema::BatchSize))
                .col(text_null(CredentialSchema::EmbeddedDisclosurePolicy))
                .col(integer_null(CredentialSchema::Expiration))
                .col(string_null(CredentialSchema::Ecosystem))
                .col(integer_null(
                    CredentialSchema::PreferredKeyStorageAttestationLifetime,
                ))
                .col(integer_null(
                    CredentialSchema::PreferredInstanceAttestationLifetime,
                ))
                .col(boolean(CredentialSchema::WuaMonitorCredentialLifetime))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-CredentialSchema-OrganisationId")
                        .from_tbl(CredentialSchemaNew::Table)
                        .from_col(CredentialSchema::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        CredentialSchema::Id,
        CredentialSchema::CreatedDate,
        CredentialSchema::LastModified,
        CredentialSchema::DeletedAt,
        CredentialSchema::Name,
        CredentialSchema::LayoutProperties,
        CredentialSchema::ImportedSourceUrl,
        CredentialSchema::AllowSuspension,
        CredentialSchema::AllowRevocation,
        CredentialSchema::RequiresWalletInstanceAttestation,
        CredentialSchema::KeyStorageSecurity,
        CredentialSchema::TransactionCodeType,
        CredentialSchema::TransactionCodeLength,
        CredentialSchema::TransactionCodeDescription,
        CredentialSchema::OrganisationId,
        CredentialSchema::BatchSize,
        CredentialSchema::EmbeddedDisclosurePolicy,
        CredentialSchema::Expiration,
        CredentialSchema::Ecosystem,
        CredentialSchema::PreferredKeyStorageAttestationLifetime,
        CredentialSchema::PreferredInstanceAttestationLifetime,
    ];
    let mut insert_columns: Vec<DynIden> = copied_columns
        .iter()
        .cloned()
        .map(IntoIden::into_iden)
        .collect();
    insert_columns.push(CredentialSchema::WuaMonitorCredentialLifetime.into_iden());
    manager
        .exec_stmt(
            Query::insert()
                .into_table(CredentialSchemaNew::Table)
                .columns(insert_columns)
                .select_from(
                    Query::select()
                        .from(CredentialSchema::Table)
                        .columns(copied_columns)
                        .expr(Expr::value(false))
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
                .name("index-CredentialSchema-CreatedDate")
                .table(CredentialSchema::Table)
                .col(CredentialSchema::CreatedDate)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-CredentialSchema-OrganisationId-DeletedAt-CreatedDate")
                .table(CredentialSchema::Table)
                .col(CredentialSchema::OrganisationId)
                .col(CredentialSchema::DeletedAt)
                .col(CredentialSchema::CreatedDate)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-CredentialSchema-Ecosystem")
                .table(CredentialSchema::Table)
                .col(CredentialSchema::Ecosystem)
                .to_owned(),
        )
        .await?;

    add_nullable_unique_idx(
        CredentialSchema::Table,
        CredentialSchema::DeletedAt,
        "index_CredentialSchema_Name-OrganisationId-DeletedAt_Unique",
        NullableIdxOpts {
            non_nullable_columns: vec![CredentialSchema::Name, CredentialSchema::OrganisationId],
            ..Default::default()
        },
        manager,
    )
    .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

#[derive(Clone, DeriveIden)]
enum CredentialSchema {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeletedAt,
    Name,
    LayoutProperties,
    ImportedSourceUrl,
    AllowSuspension,
    AllowRevocation,
    RequiresWalletInstanceAttestation,
    KeyStorageSecurity,
    TransactionCodeType,
    TransactionCodeLength,
    TransactionCodeDescription,
    OrganisationId,
    BatchSize,
    EmbeddedDisclosurePolicy,
    Expiration,
    Ecosystem,
    PreferredKeyStorageAttestationLifetime,
    PreferredInstanceAttestationLifetime,
    WuaMonitorCredentialLifetime,
}

#[derive(Clone, DeriveIden)]
enum CredentialSchemaNew {
    Table,
}
