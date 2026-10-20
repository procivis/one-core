use sea_orm_migration::prelude::*;

use crate::legacy_migrations::batch_utils::get_ids;
use crate::migrations::m20260720_091548_instance::Instance;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        remove_duplicit_instances(manager).await?;

        manager
            .drop_index(
                Index::drop()
                    .name("index-Instance-Role-OrganisationId-Unique")
                    .table(Instance::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("index-Instance-OrganisationId-Unique")
                    .unique()
                    .table(Instance::Table)
                    .col(Instance::OrganisationId)
                    .to_owned(),
            )
            .await
    }
}

// remove verifier instance where a wallet instance exists
async fn remove_duplicit_instances(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let duplicit_verifier_instance_ids: Vec<String> = get_ids(
        manager,
        Query::select()
            .column(Instance::Id)
            .from(Instance::Table)
            .and_where(Expr::col(Instance::Role).eq("VERIFIER"))
            .and_where(
                Expr::col(Instance::OrganisationId).in_subquery(
                    Query::select()
                        .column(Instance::OrganisationId)
                        .from(Instance::Table)
                        .and_where(Expr::col(Instance::Role).ne("VERIFIER"))
                        .to_owned(),
                ),
            ),
    )
    .await?;

    if duplicit_verifier_instance_ids.is_empty() {
        return Ok(());
    }

    manager
        .exec_stmt(
            Query::delete()
                .from_table(Instance::Table)
                .and_where(Expr::col(Instance::Id).is_in(duplicit_verifier_instance_ids))
                .to_owned(),
        )
        .await
}
