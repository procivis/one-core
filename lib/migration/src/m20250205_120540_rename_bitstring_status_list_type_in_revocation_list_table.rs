use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::update()
                    .table(RevocationList::Table)
                    .value(RevocationList::Type, Expr::value("BITSTRINGSTATUSLIST"))
                    .and_where(
                        Expr::col(RevocationList::Type).eq(Expr::val("BITSTRING_STATUS_LIST")),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum RevocationList {
    Table,
    Type,
}
