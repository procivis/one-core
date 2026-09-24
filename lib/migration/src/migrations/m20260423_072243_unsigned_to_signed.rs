use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::migrations::m20260417_150300_initial::{
    ClaimSchema, CredentialSchema, Notification, ProofInputClaimSchema, ProofInputSchema,
    ProofSchema, RevocationListEntry, TrustListPublication, WalletInstanceAttestation,
};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.supported_db_type() == SupportedDbType::Sqlite {
            // SQLite already uses signed integers
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .modify_column(integer_null(CredentialSchema::TransactionCodeLength))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(ClaimSchema::Table)
                    .modify_column(integer(ClaimSchema::Order))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Notification::Table)
                    .modify_column(integer(Notification::TriesCount))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(ProofSchema::Table)
                    .modify_column(big_integer(ProofSchema::ExpireDuration))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(ProofInputSchema::Table)
                    .modify_column(integer(ProofInputSchema::Order))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(ProofInputClaimSchema::Table)
                    .modify_column(integer(ProofInputClaimSchema::Order))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(RevocationListEntry::Table)
                    .modify_column(integer_null(RevocationListEntry::Index))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(TrustListPublication::Table)
                    .modify_column(integer(TrustListPublication::SequenceNumber))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(WalletInstanceAttestation::Table)
                    .modify_column(integer_null(WalletInstanceAttestation::RevocationListIndex))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
