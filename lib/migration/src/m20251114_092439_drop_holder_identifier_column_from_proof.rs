use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20250429_121331_created_date_index::PROOF_CREATED_DATE_INDEX;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => Ok(()),
            DbBackend::Sqlite => sqlite_migration(manager).await,
            DbBackend::MySql => simple_migration(manager).await,
        }
    }
}

async fn simple_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Proof::Table)
                .drop_foreign_key("fk_proof_holder_identifier")
                .drop_column(Proof::HolderIdentifierId)
                .to_owned(),
        )
        .await
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
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
                .col(
                    ColumnDef::new(ProofNew::Engagement)
                        .string()
                        .null()
                        .default("QR_CODE"),
                )
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
        ProofNew::VerifierIdentifierId,
        ProofNew::VerifierCertificateId,
        ProofNew::Profile,
        ProofNew::ProofBlobId,
        ProofNew::Engagement,
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
                .col(ProofNew::CreatedDate)
                .to_owned(),
        )
        .await?;
    Ok(())
}

#[derive(DeriveIden)]
enum Proof {
    Table,
    HolderIdentifierId,
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
    VerifierIdentifierId,
    VerifierCertificateId,
    Profile,
    ProofBlobId,
    Engagement,
}

#[derive(DeriveIden)]
enum BlobStorage {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Certificate {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Identifier {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Key {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum ProofSchema {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Interaction {
    Table,
    Id,
}
