use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::{
    Credential, CredentialSchema, Interaction, Key, RevocationList,
};
use crate::m20250429_142011_add_identifier::{
    CredentialNew as CredentialWithIdentifier, Identifier,
};
use crate::m20250512_110852_certificate::Certificate;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Sqlite => sqlite_migration(manager).await,
            _ => simple_migration(manager).await,
        }
    }
}

async fn simple_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Credential::Table)
                .add_column(
                    ColumnDef::new(CredentialNew::IssuerCertificateId)
                        .char_len(36)
                        .null(),
                )
                .add_foreign_key(
                    ForeignKey::create()
                        .name("fk-credential-issuer_certificate")
                        .from_tbl(Credential::Table)
                        .from_col(CredentialNew::IssuerCertificateId)
                        .to_tbl(Certificate::Table)
                        .to_col(Certificate::Id)
                        .get_foreign_key(),
                )
                .to_owned(),
        )
        .await
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(CredentialNew::Table)
                .col(
                    ColumnDef::new(CredentialWithIdentifier::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(CredentialWithIdentifier::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialWithIdentifier::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialWithIdentifier::IssuanceDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialWithIdentifier::DeletedAt)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .col(
                    ColumnDef::new(CredentialWithIdentifier::Exchange)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialWithIdentifier::Credential)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialWithIdentifier::CredentialSchemaId)
                        .char_len(36)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialWithIdentifier::InteractionId)
                        .char_len(36)
                        .null(),
                )
                .col(
                    ColumnDef::new(CredentialWithIdentifier::RevocationListId)
                        .char_len(36)
                        .null(),
                )
                .col(
                    ColumnDef::new(CredentialWithIdentifier::KeyId)
                        .char_len(36)
                        .null(),
                )
                .col(
                    ColumnDef::new(CredentialWithIdentifier::Role)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(CredentialWithIdentifier::RedirectUri).string_len(1000))
                .col(
                    ColumnDef::new(CredentialWithIdentifier::State)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialWithIdentifier::SuspendEndDate)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .col(
                    ColumnDef::new(CredentialWithIdentifier::HolderIdentifierId)
                        .char_len(36)
                        .null(),
                )
                .col(
                    ColumnDef::new(CredentialWithIdentifier::IssuerIdentifierId)
                        .char_len(36)
                        .null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::IssuerCertificateId)
                        .char_len(36)
                        .null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_credential_schema")
                        .from(
                            CredentialWithIdentifier::Table,
                            CredentialWithIdentifier::CredentialSchemaId,
                        )
                        .to(CredentialSchema::Table, CredentialSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_holder_identifier")
                        .from(
                            CredentialWithIdentifier::Table,
                            CredentialWithIdentifier::HolderIdentifierId,
                        )
                        .to(Identifier::Table, Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_issuer_identifier")
                        .from(
                            CredentialWithIdentifier::Table,
                            CredentialWithIdentifier::IssuerIdentifierId,
                        )
                        .to(Identifier::Table, Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_interaction")
                        .from(
                            CredentialWithIdentifier::Table,
                            CredentialWithIdentifier::InteractionId,
                        )
                        .to(Interaction::Table, Interaction::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_revocation_list")
                        .from(
                            CredentialWithIdentifier::Table,
                            CredentialWithIdentifier::RevocationListId,
                        )
                        .to(RevocationList::Table, RevocationList::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_key")
                        .from(
                            CredentialWithIdentifier::Table,
                            CredentialWithIdentifier::KeyId,
                        )
                        .to(Key::Table, Key::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-credential-issuer_certificate")
                        .from(CredentialNew::Table, CredentialNew::IssuerCertificateId)
                        .to(Certificate::Table, Certificate::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        CredentialWithIdentifier::Id,
        CredentialWithIdentifier::CreatedDate,
        CredentialWithIdentifier::LastModified,
        CredentialWithIdentifier::IssuanceDate,
        CredentialWithIdentifier::DeletedAt,
        CredentialWithIdentifier::Exchange,
        CredentialWithIdentifier::Credential,
        CredentialWithIdentifier::CredentialSchemaId,
        CredentialWithIdentifier::InteractionId,
        CredentialWithIdentifier::RevocationListId,
        CredentialWithIdentifier::KeyId,
        CredentialWithIdentifier::Role,
        CredentialWithIdentifier::RedirectUri,
        CredentialWithIdentifier::State,
        CredentialWithIdentifier::SuspendEndDate,
        CredentialWithIdentifier::HolderIdentifierId,
        CredentialWithIdentifier::IssuerIdentifierId,
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

#[derive(DeriveIden)]
pub enum CredentialNew {
    Table,
    IssuerCertificateId,
}
