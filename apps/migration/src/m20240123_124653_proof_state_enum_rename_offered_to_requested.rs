use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_query::extension::postgres::Type;

use crate::m20240110_000001_initial::{ProofRequestStateEnum, ProofState};

#[derive(Iden)]
pub(crate) enum ProofRequestState {
    #[iden = "CREATED"]
    Created,

    #[iden = "PENDING"]
    Pending,
    // Offered will be renamed to Requested
    #[iden = "OFFERED"]
    Offered,
    #[iden = "REQUESTED"]
    Requested,

    #[iden = "ACCEPTED"]
    Accepted,

    #[iden = "REJECTED"]
    Rejected,

    #[iden = "ERROR"]
    Error,
}

impl ProofRequestState {
    fn as_expr(&self) -> Expr {
        let mut s = String::new();

        self.unquoted(&mut s);

        Expr::val(s)
    }
}

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
                            .name(ProofRequestStateEnum)
                            .rename_value(ProofRequestState::Offered, ProofRequestState::Requested)
                            .to_owned(),
                    )
                    .await?;
            }
            sea_orm::DatabaseBackend::MySql => {
                // Add the new enum variant
                manager
                    .alter_table(
                        Table::alter()
                            .table(ProofState::Table)
                            .modify_column(ColumnDef::new(ProofState::State).enumeration(
                                ProofRequestStateEnum,
                                [
                                    ProofRequestState::Created,
                                    ProofRequestState::Pending,
                                    ProofRequestState::Offered,
                                    ProofRequestState::Accepted,
                                    ProofRequestState::Rejected,
                                    ProofRequestState::Error,
                                    // new enum variant
                                    ProofRequestState::Requested,
                                ],
                            ))
                            .to_owned(),
                    )
                    .await?;

                // Rename offered enum entries to requested
                manager
                    .exec_stmt(
                        Query::update()
                            .table(ProofState::Table)
                            .value(
                                ProofState::State,
                                ProofRequestState::Requested
                                    .as_expr()
                                    .as_enum(ProofRequestStateEnum),
                            )
                            .and_where(
                                Expr::col(ProofState::State).eq(ProofRequestState::Offered
                                    .as_expr()
                                    .as_enum(ProofRequestStateEnum)),
                            )
                            .to_owned(),
                    )
                    .await?;

                // Remove offered enum variant
                manager
                    .alter_table(
                        Table::alter()
                            .table(ProofState::Table)
                            .modify_column(ColumnDef::new(ProofState::State).enumeration(
                                ProofRequestStateEnum,
                                [
                                    ProofRequestState::Created,
                                    ProofRequestState::Pending,
                                    ProofRequestState::Accepted,
                                    ProofRequestState::Rejected,
                                    ProofRequestState::Error,
                                    ProofRequestState::Requested,
                                ],
                            ))
                            .to_owned(),
                    )
                    .await?;
            }
            sea_orm::DatabaseBackend::Sqlite => {
                manager
                    .exec_stmt(
                        Query::update()
                            .table(ProofState::Table)
                            .value(ProofState::State, ProofRequestState::Requested.as_expr())
                            .and_where(
                                Expr::col(ProofState::State)
                                    .eq(ProofRequestState::Offered.as_expr()),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
        };

        Ok(())
    }
}
