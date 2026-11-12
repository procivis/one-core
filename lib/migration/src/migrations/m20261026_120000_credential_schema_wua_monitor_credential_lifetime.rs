use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{
    boolean, integer_null, json_binary_null, string, string_len_null, string_null, text_null,
};
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::datatype::{timestamp, timestamp_null, uuid_char};
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
        .recreate_table(
            Table::recreate()
                .table(CredentialSchema::Table)
                .modify_column(uuid_char(CredentialSchema::Id).primary_key())
                .modify_column(timestamp(CredentialSchema::CreatedDate, manager))
                .modify_column(timestamp(CredentialSchema::LastModified, manager))
                .modify_column(timestamp_null(CredentialSchema::DeletedAt, manager))
                .modify_column(string(CredentialSchema::Name))
                .modify_column(json_binary_null(CredentialSchema::LayoutProperties))
                .modify_column(string(CredentialSchema::ImportedSourceUrl))
                .modify_column(boolean(CredentialSchema::AllowSuspension))
                .modify_column(boolean(CredentialSchema::AllowRevocation))
                .modify_column(boolean(CredentialSchema::RequiresWalletInstanceAttestation))
                .modify_column(string_null(CredentialSchema::KeyStorageSecurity))
                .modify_column(string_null(CredentialSchema::TransactionCodeType))
                .modify_column(integer_null(CredentialSchema::TransactionCodeLength))
                .modify_column(string_len_null(
                    CredentialSchema::TransactionCodeDescription,
                    300,
                ))
                .modify_column(uuid_char(CredentialSchema::OrganisationId))
                .modify_column(integer_null(CredentialSchema::BatchSize))
                .modify_column(text_null(CredentialSchema::EmbeddedDisclosurePolicy))
                .modify_column(integer_null(CredentialSchema::Expiration))
                .modify_column(string_null(CredentialSchema::Ecosystem))
                .modify_column(integer_null(
                    CredentialSchema::PreferredKeyStorageAttestationLifetime,
                ))
                .modify_column(integer_null(
                    CredentialSchema::PreferredInstanceAttestationLifetime,
                ))
                .add_column_with_value(
                    boolean(CredentialSchema::WuaMonitorCredentialLifetime),
                    Expr::value(false),
                )
                .to_owned(),
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
