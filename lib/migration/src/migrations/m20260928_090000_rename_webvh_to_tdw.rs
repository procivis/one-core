use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::Did;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::update()
                    .table(Did::Table)
                    .value(Did::Method, "TDW")
                    .and_where(Expr::col(Did::Method).eq("WEBVH"))
                    .to_owned(),
            )
            .await
    }
}
