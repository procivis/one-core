use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::{
    Credential, CredentialSchema, Interaction, Key, RevocationList,
};
use crate::m20250429_142011_add_identifier::Identifier;
use crate::m20250512_110852_certificate::Certificate;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Sqlite => sqlite_migration(manager).await,
            _ => migrate(manager).await,
        }
    }
}

async fn migrate(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Credential::Table)
                .modify_column(
                    ColumnDef::new(Credential::IssuanceDate)
                        .datetime_millisecond_precision(manager)
                        .null(),
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
                        .null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::DeletedAt)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .col(ColumnDef::new(CredentialNew::Protocol).string().not_null())
                .col(
                    ColumnDef::new(CredentialNew::CredentialSchemaId)
                        .char_len(36)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::InteractionId)
                        .char_len(36)
                        .null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::RevocationListId)
                        .char_len(36)
                        .null(),
                )
                .col(ColumnDef::new(CredentialNew::KeyId).char_len(36).null())
                .col(ColumnDef::new(CredentialNew::Role).string().not_null())
                .col(ColumnDef::new(CredentialNew::RedirectUri).string_len(1000))
                .col(ColumnDef::new(CredentialNew::State).string().not_null())
                .col(
                    ColumnDef::new(CredentialNew::SuspendEndDate)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::HolderIdentifierId)
                        .char_len(36)
                        .null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::IssuerIdentifierId)
                        .char_len(36)
                        .null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::IssuerCertificateId)
                        .char_len(36)
                        .null(),
                )
                .col(ColumnDef::new(CredentialNew::Profile).string().null())
                .col(
                    ColumnDef::new(CredentialNew::CredentialBlobId)
                        .char_len(36)
                        .null(),
                )
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
        CredentialNew::Id,
        CredentialNew::CreatedDate,
        CredentialNew::LastModified,
        CredentialNew::IssuanceDate,
        CredentialNew::DeletedAt,
        CredentialNew::Protocol,
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
        CredentialNew::IssuerCertificateId,
        CredentialNew::Profile,
        CredentialNew::CredentialBlobId,
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

    manager
        .create_index(
            Index::create()
                .name(crate::m20250708_110608_credential_list_indexes::CREDENTIAL_ROLE_INDEX)
                .table(Credential::Table)
                .col(crate::m20240118_070610_credential_add_role::CredentialNew::Role)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name(crate::m20250708_110608_credential_list_indexes::CREDENTIAL_DELETED_AT_INDEX)
                .table(Credential::Table)
                .col(Credential::DeletedAt)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name(crate::m20250708_110608_credential_list_indexes::CREDENTIAL_STATE_INDEX)
                .table(Credential::Table)
                .col(crate::m20241212_08000_migrate_credential_state::Credential::State)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name(crate::m20250708_110608_credential_list_indexes::CREDENTIAL_SUSPEND_END_DATE_INDEX)
                .table(Credential::Table)
                .col(crate::m20241212_08000_migrate_credential_state::Credential::SuspendEndDate)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name(crate::m20250429_121331_created_date_index::CREDENTIAL_CREATED_DATE_INDEX)
                .table(Credential::Table)
                .col(Credential::CreatedDate)
                .to_owned(),
        )
        .await?;

    Ok(())
}

#[derive(DeriveIden, Clone)]
pub enum CredentialNew {
    Table,
    Id,
    CreatedDate,
    LastModified,
    IssuanceDate,
    DeletedAt,
    Protocol,
    CredentialSchemaId,
    InteractionId,
    RevocationListId,
    KeyId,
    Role,
    RedirectUri,
    State,
    SuspendEndDate,
    HolderIdentifierId,
    IssuerIdentifierId,
    IssuerCertificateId,
    Profile,
    CredentialBlobId,
}
