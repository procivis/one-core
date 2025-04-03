use sea_orm_migration::prelude::*;

use crate::m20240625_090000_proof_exchange_to_transport::Proof;
use crate::m20250314_114529_rename_transport_to_exchange::Credential;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::update()
                    .table(Credential::Table)
                    .value(Credential::Exchange, "OPENID4VCI_DRAFT13".to_string())
                    .and_where(Expr::col(Credential::Exchange).eq(Expr::val("OPENID4VC")))
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(Proof::Table)
                    .value(Proof::Exchange, "OPENID4VP_DRAFT20".to_string())
                    .and_where(Expr::col(Proof::Exchange).eq(Expr::val("OPENID4VC")))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
