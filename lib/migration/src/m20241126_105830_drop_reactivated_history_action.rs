use sea_orm::{EnumIter, Iterable};
use sea_orm_migration::prelude::*;

use crate::m20240130_105023_add_history::{History, HistoryAction};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        manager.exec_stmt(
            Query::delete()
                .from_table(History::Table)
                .and_where(
                    Expr::col(History::Action)
                        .eq(crate::m20240307_103000_add_reactivated_history_action::UpdatedHistoryAction::Reactivated.as_expr()),
                )
                .to_owned()
        ).await?;

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
}
