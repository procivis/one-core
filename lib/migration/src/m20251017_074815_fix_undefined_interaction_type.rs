use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .exec_stmt(
                Query::update()
                    .table(Interaction::Table)
                    .value(
                        Interaction::InteractionType,
                        Expr::case(
                            Expr::column(Interaction::Data)
                                .like(r#"%"access_token"%"#)
                                .or(Expr::column(Interaction::Data)
                                    .like(r#"%"continue_issuance"%"#))
                                .or(Expr::column(Interaction::Data)
                                    .like(r#"%"pre-authorized_code"%"#))
                                .or(Expr::column(Interaction::Data)
                                    .like(r#"%"pre_authorized_code_used"%"#))
                                .or(Expr::column(Interaction::Data)
                                    .like(r#"%"protocol":"OPENID4VCI_DRAFT13"%"#))
                                .or(Expr::column(Interaction::Data).like(r#"%openid4vci%"#)),
                            Expr::val("ISSUANCE"),
                        )
                        .case(
                            Expr::column(Interaction::Data)
                                .like(r#"%"presentation_definition"%"#)
                                .or(Expr::column(Interaction::Data).like(r#"%vp_token%"#))
                                .or(Expr::column(Interaction::Data).like(r#"%openid4vp%"#)),
                            Expr::val("VERIFICATION"),
                        )
                        .finally("UNDEFINED"),
                    )
                    .cond_where(
                        Expr::column((Interaction::Table, Interaction::InteractionType))
                            .eq(Expr::val("UNDEFINED")),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::delete()
                    .from_table(Interaction::Table)
                    .cond_where(
                        Expr::column((Interaction::Table, Interaction::InteractionType))
                            .eq(Expr::val("UNDEFINED")),
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
    InteractionType,
    Data,
}
