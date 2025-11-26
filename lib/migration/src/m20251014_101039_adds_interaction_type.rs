use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Postgres {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(Interaction::Table)
                    .add_column_if_not_exists(
                        string(Interaction::InteractionType).default("UNDEFINED"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(Interaction::Table)
                    .value(
                        Interaction::InteractionType,
                        Expr::case(
                            Expr::exists(
                                Query::select()
                                    .expr(Expr::val(1))
                                    .from(Credential::Table)
                                    .cond_where(
                                        Expr::column((
                                            Credential::Table,
                                            Credential::InteractionId,
                                        ))
                                        .eq(Expr::column((Interaction::Table, Interaction::Id))),
                                    )
                                    .to_owned(),
                            ),
                            Expr::val("ISSUANCE"),
                        )
                        .case(
                            Expr::exists(
                                Query::select()
                                    .expr(Expr::val(1))
                                    .from(Proof::Table)
                                    .cond_where(
                                        Expr::column((Proof::Table, Proof::InteractionId)).eq(
                                            Expr::column((Interaction::Table, Interaction::Id)),
                                        ),
                                    )
                                    .to_owned(),
                            ),
                            Expr::val("VERIFICATION"),
                        )
                        .finally("UNDEFINED"),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[expect(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Interaction {
    Table,
    Id,
    InteractionType,
}

#[derive(DeriveIden)]
enum Credential {
    Table,
    InteractionId,
}

#[derive(DeriveIden)]
enum Proof {
    Table,
    InteractionId,
}
