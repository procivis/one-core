use crate::extension::postgres::Type;
use crate::m20240130_105023_add_history::{History, HistoryAction};
use sea_orm::EnumIter;
use sea_orm::Iterable;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => {
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

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "One way migration - cannot remove REACTIVATED variant from history action".to_owned(),
        ))
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
    #[iden = "REACTIVATED"]
    Reactivated,
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