use sea_orm::{EnumIter, Iterable};
use sea_orm_migration::prelude::*;

use crate::extension::postgres::Type;
use crate::m20240110_000001_initial::CustomDateTime;
use crate::m20240130_105023_add_history::{History, HistoryAction};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let datetime = CustomDateTime(manager.get_database_backend());
        match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => {
                manager
                    .exec_stmt(
                        Type::alter()
                            .name(State::Table)
                            .add_value(UpdatedStates::Suspended)
                            .to_owned(),
                    )
                    .await?;
                manager
                    .exec_stmt(
                        Type::alter()
                            .name(HistoryAction::Table)
                            .add_value(UpdatedHistoryAction::Suspended)
                            .to_owned(),
                    )
                    .await?;
            }
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
                            .custom(datetime)
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "One way migration - cannot remove SUSPEND variant from history action and credential status".to_owned(),
        ))
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
