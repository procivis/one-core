use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{EnumIter, Iterable};
use sea_orm_migration::sea_query::extension::postgres::Type;

use crate::m20240130_105023_add_history::{History, HistoryAction};

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
                            .add_value(UpdatedHistoryAction::Errored)
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
}
