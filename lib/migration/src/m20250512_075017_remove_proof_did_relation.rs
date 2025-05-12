use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::{Interaction, Key, Proof, ProofSchema};
use crate::m20250429_142011_add_identifier::{Identifier, ProofNew};

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
                .table(ProofNew::Table)
                .if_not_exists()
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
                    ColumnDef::new(ProofNew::IssuanceDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(ColumnDef::new(ProofNew::RedirectUri).string_len(1000))
                .col(ColumnDef::new(ProofNew::ProofSchemaId).char_len(36))
                .col(ColumnDef::new(ProofNew::Transport).string().not_null())
                .col(ColumnDef::new(ProofNew::VerifierKeyId).char_len(36))
                .col(ColumnDef::new(ProofNew::InteractionId).char_len(36))
                .col(ColumnDef::new(ProofNew::Exchange).string().not_null())
                .col(ColumnDef::new(ProofNew::State).string().not_null())
                .col(
                    ColumnDef::new(ProofNew::RequestedDate).datetime_millisecond_precision(manager),
                )
                .col(
                    ColumnDef::new(ProofNew::CompletedDate).datetime_millisecond_precision(manager),
                )
                .col(ColumnDef::new(ProofNew::Role).string().not_null())
                .col(ColumnDef::new(ProofNew::HolderIdentifierId).char_len(36))
                .col(ColumnDef::new(ProofNew::VerifierIdentifierId).char_len(36))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_proof_schema")
                        .from(ProofNew::Table, ProofNew::ProofSchemaId)
                        .to(ProofSchema::Table, ProofSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_interaction")
                        .from(ProofNew::Table, ProofNew::InteractionId)
                        .to(Interaction::Table, Interaction::Id),
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
                        .name("fk_proof_verifier_key")
                        .from(ProofNew::Table, ProofNew::VerifierKeyId)
                        .to(Key::Table, Key::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        ProofNew::Id,
        ProofNew::CreatedDate,
        ProofNew::LastModified,
        ProofNew::IssuanceDate,
        ProofNew::RedirectUri,
        ProofNew::ProofSchemaId,
        ProofNew::Transport,
        ProofNew::VerifierKeyId,
        ProofNew::InteractionId,
        ProofNew::Exchange,
        ProofNew::State,
        ProofNew::RequestedDate,
        ProofNew::CompletedDate,
        ProofNew::Role,
        ProofNew::HolderIdentifierId,
        ProofNew::VerifierIdentifierId,
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

async fn mysql_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Proof::Table)
                .drop_foreign_key(Alias::new("fk-Proof-VerifierDidId"))
                .drop_foreign_key(Alias::new("fk-Proof-HolderDidId"))
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(Proof::Table)
                .drop_column(Proof::VerifierDidId)
                .drop_column(Proof::HolderDidId)
                .to_owned(),
        )
        .await
}
