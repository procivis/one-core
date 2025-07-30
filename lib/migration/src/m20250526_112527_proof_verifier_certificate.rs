use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::{Interaction, Key, Proof, ProofSchema};
use crate::m20250429_142011_add_identifier::{Identifier, ProofNew as ProofWithIdentifiers};
use crate::m20250512_110852_certificate::Certificate;

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
                .add_column(
                    ColumnDef::new(ProofNew::VerifierCertificateId)
                        .char_len(36)
                        .null(),
                )
                .add_foreign_key(
                    ForeignKey::create()
                        .name("fk-proof-verifier_certificate")
                        .from_tbl(Proof::Table)
                        .from_col(ProofNew::VerifierCertificateId)
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
                .table(ProofNew::Table)
                .col(
                    ColumnDef::new(ProofWithIdentifiers::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(ProofWithIdentifiers::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ProofWithIdentifiers::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ProofWithIdentifiers::IssuanceDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(ColumnDef::new(ProofWithIdentifiers::RedirectUri).string_len(1000))
                .col(ColumnDef::new(ProofWithIdentifiers::ProofSchemaId).char_len(36))
                .col(
                    ColumnDef::new(ProofWithIdentifiers::Transport)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(ProofWithIdentifiers::VerifierKeyId).char_len(36))
                .col(ColumnDef::new(ProofWithIdentifiers::InteractionId).char_len(36))
                .col(
                    ColumnDef::new(ProofWithIdentifiers::Exchange)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ProofWithIdentifiers::State)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ProofWithIdentifiers::RequestedDate)
                        .datetime_millisecond_precision(manager),
                )
                .col(
                    ColumnDef::new(ProofWithIdentifiers::CompletedDate)
                        .datetime_millisecond_precision(manager),
                )
                .col(
                    ColumnDef::new(ProofWithIdentifiers::Role)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(ProofWithIdentifiers::HolderIdentifierId).char_len(36))
                .col(ColumnDef::new(ProofWithIdentifiers::VerifierIdentifierId).char_len(36))
                .col(ColumnDef::new(ProofNew::VerifierCertificateId).char_len(36))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_proof_schema")
                        .from(ProofNew::Table, ProofWithIdentifiers::ProofSchemaId)
                        .to(ProofSchema::Table, ProofSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_interaction")
                        .from(ProofNew::Table, ProofWithIdentifiers::InteractionId)
                        .to(Interaction::Table, Interaction::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_holder_identifier")
                        .from(ProofNew::Table, ProofWithIdentifiers::HolderIdentifierId)
                        .to(Identifier::Table, Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_verifier_identifier")
                        .from(ProofNew::Table, ProofWithIdentifiers::VerifierIdentifierId)
                        .to(Identifier::Table, Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_verifier_key")
                        .from(ProofNew::Table, ProofWithIdentifiers::VerifierKeyId)
                        .to(Key::Table, Key::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-proof-verifier_certificate")
                        .from_tbl(ProofNew::Table)
                        .from_col(ProofNew::VerifierCertificateId)
                        .to_tbl(Certificate::Table)
                        .to_col(Certificate::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        ProofWithIdentifiers::Id,
        ProofWithIdentifiers::CreatedDate,
        ProofWithIdentifiers::LastModified,
        ProofWithIdentifiers::IssuanceDate,
        ProofWithIdentifiers::RedirectUri,
        ProofWithIdentifiers::ProofSchemaId,
        ProofWithIdentifiers::Transport,
        ProofWithIdentifiers::VerifierKeyId,
        ProofWithIdentifiers::InteractionId,
        ProofWithIdentifiers::Exchange,
        ProofWithIdentifiers::State,
        ProofWithIdentifiers::RequestedDate,
        ProofWithIdentifiers::CompletedDate,
        ProofWithIdentifiers::Role,
        ProofWithIdentifiers::HolderIdentifierId,
        ProofWithIdentifiers::VerifierIdentifierId,
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

    Ok(())
}

#[derive(DeriveIden)]
pub enum ProofNew {
    Table,
    VerifierCertificateId,
}
