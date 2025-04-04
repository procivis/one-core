use sea_orm::{EnumIter, Iterable};
use sea_orm_migration::prelude::*;

use crate::m20240130_105023_add_history::{History, HistoryAction};
use crate::m20241210_154315_remove_proof_state_table::Proof;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            sea_orm::DatabaseBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(History::Table)
                            .modify_column(
                                ColumnDef::new(History::Action)
                                    .enumeration(HistoryAction::Table, UpdatedHistoryAction::iter())
                                    .not_null(),
                            )
                            .to_owned(),
                    )
                    .await?;
                manager
                    .alter_table(
                        Table::alter()
                            .table(Proof::Table)
                            .modify_column(
                                ColumnDef::new(Proof::State)
                                    .enumeration(Proof::Table, ProofRequestState::iter())
                                    .not_null(),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            sea_orm::DatabaseBackend::Postgres | sea_orm::DatabaseBackend::Sqlite => {}
        };
        Ok(())
    }
}

#[derive(Iden, EnumIter)]
pub enum UpdatedHistoryAction {
    #[iden = "ACCEPTED"]
    Accepted,
    #[iden = "CREATED"]
    Created,
    #[iden = "DEACTIVATED"]
    Deactivated,
    #[iden = "DELETED"]
    Deleted,
    #[iden = "ISSUED"]
    Issued,
    #[iden = "OFFERED"]
    Offered,
    #[iden = "REJECTED"]
    Rejected,
    #[iden = "REQUESTED"]
    Requested,
    #[iden = "RESTORED"]
    Restored,
    #[iden = "REVOKED"]
    Revoked,
    #[iden = "PENDING"]
    Pending,
    #[iden = "SUSPENDED"]
    Suspended,
    #[iden = "ERRORED"]
    Errored,
    #[iden = "SHARED"]
    Shared,
    #[iden = "IMPORTED"]
    Imported,
    #[iden = "CLAIMS_REMOVED"]
    ClaimsRemoved,
    #[iden = "ACTIVATED"]
    Activated,
    #[iden = "WITHDRAWN"]
    Withdrawn,
    #[iden = "REMOVED"]
    Removed,
    #[iden = "RETRACTED"]
    Retracted, // new variant
}

#[derive(Iden, EnumIter)]
pub(crate) enum ProofRequestState {
    #[iden = "CREATED"]
    Created,
    #[iden = "PENDING"]
    Pending,
    #[iden = "REQUESTED"]
    Requested,
    #[iden = "ACCEPTED"]
    Accepted,
    #[iden = "REJECTED"]
    Rejected,
    #[iden = "RETRACTED"]
    Retracted, // new variant
    #[iden = "ERROR"]
    Error,
}
