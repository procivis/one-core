use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::History;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(History::Table)
                    .cond_where(Expr::col(History::EntityType).eq("WALLET_UNIT"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
