use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::{
    Credential, CredentialSchema, Interaction, Key, RevocationList,
};
use crate::m20250429_142011_add_identifier::{CredentialNew, Identifier};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Sqlite => sqlite_migration(manager).await,
            _ => mysql_migration(manager).await,
        }
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(CredentialNew::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(CredentialNew::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(CredentialNew::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::IssuanceDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::DeletedAt)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .col(ColumnDef::new(CredentialNew::Exchange).string().not_null())
                .col(
                    ColumnDef::new(CredentialNew::Credential)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::CredentialSchemaId)
                        .char_len(36)
                        .not_null(),
                )
                .col(ColumnDef::new(CredentialNew::InteractionId).char_len(36))
                .col(ColumnDef::new(CredentialNew::RevocationListId).char_len(36))
                .col(ColumnDef::new(CredentialNew::KeyId).char_len(36))
                .col(ColumnDef::new(CredentialNew::Role).string().not_null())
                .col(ColumnDef::new(CredentialNew::RedirectUri).string_len(1000))
                .col(ColumnDef::new(CredentialNew::State).string().not_null())
                .col(
                    ColumnDef::new(CredentialNew::SuspendEndDate)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .col(ColumnDef::new(CredentialNew::HolderIdentifierId).char_len(36))
                .col(ColumnDef::new(CredentialNew::IssuerIdentifierId).char_len(36))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_credential_schema")
                        .from(CredentialNew::Table, CredentialNew::CredentialSchemaId)
                        .to(CredentialSchema::Table, CredentialSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_holder_identifier")
                        .from(CredentialNew::Table, CredentialNew::HolderIdentifierId)
                        .to(Identifier::Table, Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_issuer_identifier")
                        .from(CredentialNew::Table, CredentialNew::IssuerIdentifierId)
                        .to(Identifier::Table, Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_interaction")
                        .from(CredentialNew::Table, CredentialNew::InteractionId)
                        .to(Interaction::Table, Interaction::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_revocation_list")
                        .from(CredentialNew::Table, CredentialNew::RevocationListId)
                        .to(RevocationList::Table, RevocationList::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_key")
                        .from(CredentialNew::Table, CredentialNew::KeyId)
                        .to(Key::Table, Key::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        CredentialNew::Id,
        CredentialNew::CreatedDate,
        CredentialNew::LastModified,
        CredentialNew::IssuanceDate,
        CredentialNew::DeletedAt,
        CredentialNew::Exchange,
        CredentialNew::Credential,
        CredentialNew::CredentialSchemaId,
        CredentialNew::InteractionId,
        CredentialNew::RevocationListId,
        CredentialNew::KeyId,
        CredentialNew::Role,
        CredentialNew::RedirectUri,
        CredentialNew::State,
        CredentialNew::SuspendEndDate,
        CredentialNew::HolderIdentifierId,
        CredentialNew::IssuerIdentifierId,
    ];

    manager
        .exec_stmt(
            Query::insert()
                .into_table(CredentialNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(Credential::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Disable foreign keys for SQLite
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    manager
        .drop_table(Table::drop().table(Credential::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(CredentialNew::Table, Credential::Table)
                .to_owned(),
        )
        .await?;

    // Enable foreign keys for SQLite
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

async fn mysql_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Credential::Table)
                .drop_foreign_key(Alias::new("fk-Credential-IssuerDidId"))
                .drop_foreign_key(Alias::new("fk-Credential-HolderDidId"))
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(Credential::Table)
                .drop_column(Credential::IssuerDidId)
                .drop_column(Credential::HolderDidId)
                .to_owned(),
        )
        .await
}
