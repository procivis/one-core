use sea_orm::{EnumIter, Iterable};
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240130_105023_add_history::{History, HistoryAction};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            // Skip because it is not supported. If support for Postgres is added in the future,
            // the schema can be setup in its entirety in a new, later migration
            sea_orm::DatabaseBackend::Postgres => return Ok(()),
            sea_orm::DatabaseBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(CredentialState::Table)
                            .modify_column(
                                ColumnDef::new(CredentialState::State)
                                    .enumeration(State::Table, UpdatedStates::iter()),
                            )
                            .to_owned(),
                    )
                    .await?;
                manager
                    .alter_table(
                        Table::alter()
                            .table(History::Table)
                            .modify_column(
                                ColumnDef::new(History::Action).enumeration(
                                    HistoryAction::Table,
                                    UpdatedHistoryAction::iter(),
                                ),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            sea_orm::DatabaseBackend::Sqlite => {}
        };

        manager
            .alter_table(
                Table::alter()
                    .table(CredentialState::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(CredentialState::SuspendEndDate)
                            .datetime_millisecond_precision(manager)
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum CredentialState {
    Table,
    State,
    SuspendEndDate,
}

#[derive(Iden)]
pub enum State {
    Table,
}

#[derive(Iden, EnumIter)]
pub enum UpdatedStates {
    #[iden = "CREATED"]
    Created,
    #[iden = "PENDING"]
    Pending,
    #[iden = "OFFERED"]
    Offered,
    #[iden = "ACCEPTED"]
    Accepted,
    #[iden = "REJECTED"]
    Rejected,
    #[iden = "REVOKED"]
    Revoked,
    #[iden = "SUSPENDED"]
    Suspended,
    #[iden = "ERROR"]
    Error,
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
    #[iden = "REVOKED"]
    Revoked,
    #[iden = "PENDING"]
    Pending,
    #[iden = "SUSPENDED"]
    Suspended,
}
