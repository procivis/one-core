use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::Proof;

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
        // Add role column and initialize as VERIFIER
        manager
            .alter_table(
                Table::alter()
                    .table(Proof::Table)
                    .add_column(
                        ColumnDef::new(ProofNew::Role)
                            .enumeration(ProofRole::Table, [ProofRole::Holder, ProofRole::Verifier])
                            .default(ProofRole::Verifier.as_expr())
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Set role to HOLDER for all proofs that do not have a schema
        manager
            .exec_stmt(
                Query::update()
                    .table(Proof::Table)
                    .value(ProofNew::Role, ProofRole::Holder.as_expr())
                    .and_where(Expr::col(Proof::ProofSchemaId).is_null())
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
enum ProofNew {
    Role,
}

#[derive(Iden)]
enum ProofRole {
    Table,
    #[iden = "HOLDER"]
    Holder,
    #[iden = "VERIFIER"]
    Verifier,
}

impl ProofRole {
    fn as_expr(&self) -> Expr {
        let mut s = String::new();

        self.unquoted(&mut s);

        Expr::val(s)
    }
}
