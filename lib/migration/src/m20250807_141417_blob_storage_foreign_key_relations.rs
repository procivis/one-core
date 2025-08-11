use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::{
    CredentialSchema, Interaction, Key, ProofSchema, RevocationList,
};
use crate::m20250429_121331_created_date_index::PROOF_CREATED_DATE_INDEX;
use crate::m20250429_142011_add_identifier::Identifier;
use crate::m20250512_110852_certificate::Certificate;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => Ok(()),
            DbBackend::MySql => {
                clear_credential_orphans_blob_ids(manager).await?;
                manager
                    .alter_table(
                        Table::alter()
                            .table(Credential::Table)
                            .add_foreign_key(
                                TableForeignKey::new()
                                    .name("fk_credential_credential_blob_id")
                                    .from_tbl(Credential::Table)
                                    .from_col(Credential::CredentialBlobId)
                                    .to_tbl(BlobStorage::Table)
                                    .to_col(BlobStorage::Id)
                                    .on_delete(ForeignKeyAction::SetNull),
                            )
                            .to_owned(),
                    )
                    .await?;

                clear_proof_orphans_blob_ids(manager).await?;
                manager
                    .alter_table(
                        Table::alter()
                            .table(Proof::Table)
                            .add_foreign_key(
                                TableForeignKey::new()
                                    .name("fk_proof_proof_blob_id")
                                    .from_tbl(Proof::Table)
                                    .from_col(Proof::ProofBlobId)
                                    .to_tbl(BlobStorage::Table)
                                    .to_col(BlobStorage::Id)
                                    .on_delete(ForeignKeyAction::SetNull),
                            )
                            .to_owned(),
                    )
                    .await?;

                Ok(())
            }
            DbBackend::Sqlite => {
                clear_credential_orphans_blob_ids(manager).await?;
                sqlite_migration_credential(manager).await?;

                clear_proof_orphans_blob_ids(manager).await?;
                sqlite_migration_proof(manager).await?;
                Ok(())
            }
        }
    }
}

async fn sqlite_migration_credential(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
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
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_credential_blob_id")
                        .from(CredentialNew::Table, CredentialNew::CredentialBlobId)
                        .to(BlobStorage::Table, BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull),
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

async fn sqlite_migration_proof(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(ProofNew::Table)
                .col(
                    ColumnDef::new(ProofNew::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(ProofNew::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ProofNew::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ProofNew::RedirectUri)
                        .string_len(1000)
                        .null(),
                )
                .col(ColumnDef::new(ProofNew::ProofSchemaId).char_len(36).null())
                .col(ColumnDef::new(ProofNew::Transport).string().not_null())
                .col(ColumnDef::new(ProofNew::InteractionId).char_len(36).null())
                .col(ColumnDef::new(ProofNew::VerifierKeyId).char_len(36).null())
                .col(ColumnDef::new(ProofNew::Protocol).string().not_null())
                .col(ColumnDef::new(ProofNew::State).string().not_null())
                .col(
                    ColumnDef::new(ProofNew::RequestedDate)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .col(
                    ColumnDef::new(ProofNew::CompletedDate)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .col(ColumnDef::new(ProofNew::Role).string().not_null())
                .col(
                    ColumnDef::new(ProofNew::HolderIdentifierId)
                        .char_len(36)
                        .null(),
                )
                .col(
                    ColumnDef::new(ProofNew::VerifierIdentifierId)
                        .char_len(36)
                        .null(),
                )
                .col(
                    ColumnDef::new(ProofNew::VerifierCertificateId)
                        .char_len(36)
                        .null(),
                )
                .col(ColumnDef::new(ProofNew::Profile).string().null())
                .col(ColumnDef::new(ProofNew::ProofBlobId).char_len(36).null())
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Proof-InteractionId")
                        .from(ProofNew::Table, ProofNew::InteractionId)
                        .to(Interaction::Table, Interaction::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Proof-ProofSchemaId")
                        .from(ProofNew::Table, ProofNew::ProofSchemaId)
                        .to(ProofSchema::Table, ProofSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Proof-VerifierKeyId")
                        .from(ProofNew::Table, ProofNew::VerifierKeyId)
                        .to(Key::Table, Key::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-proof-verifier_certificate")
                        .from(ProofNew::Table, ProofNew::VerifierCertificateId)
                        .to(Certificate::Table, Certificate::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_holder_identifier")
                        .from(ProofNew::Table, ProofNew::HolderIdentifierId)
                        .to(Identifier::Table, Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_verifier_identifier")
                        .from(ProofNew::Table, ProofNew::VerifierIdentifierId)
                        .to(Identifier::Table, Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_proof_blob_id")
                        .from(ProofNew::Table, ProofNew::ProofBlobId)
                        .to(BlobStorage::Table, BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        ProofNew::Id,
        ProofNew::CreatedDate,
        ProofNew::LastModified,
        ProofNew::RedirectUri,
        ProofNew::ProofSchemaId,
        ProofNew::Transport,
        ProofNew::InteractionId,
        ProofNew::VerifierKeyId,
        ProofNew::Protocol,
        ProofNew::State,
        ProofNew::RequestedDate,
        ProofNew::CompletedDate,
        ProofNew::Role,
        ProofNew::HolderIdentifierId,
        ProofNew::VerifierIdentifierId,
        ProofNew::VerifierCertificateId,
        ProofNew::Profile,
        ProofNew::ProofBlobId,
    ];

    manager
        .exec_stmt(
            Query::insert()
                .into_table(ProofNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(Proof::Table)
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
        .drop_table(Table::drop().table(Proof::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(ProofNew::Table, Proof::Table)
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
                .name(PROOF_CREATED_DATE_INDEX)
                .table(Proof::Table)
                .col(Proof::CreatedDate)
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn clear_credential_orphans_blob_ids(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .exec_stmt(
            Query::update()
                .table(Credential::Table)
                .value(Credential::CredentialBlobId, Value::String(None))
                .cond_where(
                    Condition::all()
                        .add(
                            Expr::col((Credential::Table, Credential::CredentialBlobId))
                                .is_not_null(),
                        )
                        .add(
                            Expr::col((Credential::Table, Credential::CredentialBlobId))
                                .not_in_subquery(
                                    Query::select()
                                        .from(BlobStorage::Table)
                                        .column(BlobStorage::Id)
                                        .to_owned(),
                                ),
                        ),
                )
                .to_owned(),
        )
        .await
}

async fn clear_proof_orphans_blob_ids(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .exec_stmt(
            Query::update()
                .table(Proof::Table)
                .value(Proof::ProofBlobId, Value::String(None))
                .cond_where(
                    Condition::all()
                        .add(Expr::col((Proof::Table, Proof::ProofBlobId)).is_not_null())
                        .add(
                            Expr::col((Proof::Table, Proof::ProofBlobId)).not_in_subquery(
                                Query::select()
                                    .from(BlobStorage::Table)
                                    .column(BlobStorage::Id)
                                    .to_owned(),
                            ),
                        ),
                )
                .to_owned(),
        )
        .await
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

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden, Clone)]
enum Credential {
    Table,
    CredentialBlobId,
    DeletedAt,
    CreatedDate,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden, Clone)]
enum ProofNew {
    Table,
    Id,
    CreatedDate,
    LastModified,
    RedirectUri,
    ProofSchemaId,
    Transport,
    InteractionId,
    VerifierKeyId,
    Protocol,
    State,
    RequestedDate,
    CompletedDate,
    Role,
    HolderIdentifierId,
    VerifierIdentifierId,
    VerifierCertificateId,
    Profile,
    ProofBlobId,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Proof {
    Table,
    CreatedDate,
    ProofBlobId,
}

#[derive(DeriveIden)]
enum BlobStorage {
    Table,
    Id,
}
