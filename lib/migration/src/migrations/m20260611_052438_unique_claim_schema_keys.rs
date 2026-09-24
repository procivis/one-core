use sea_orm::FromQueryResult;
use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::{Claim, ClaimSchema};
use crate::migrations::m20260429_120000_credential_schema_multiformat::CredentialSchemaFormatClaimSchema;
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("index-ClaimSchema-Key-CredentialSchemaId-Unique")
                    .unique()
                    .table(ClaimSchema::Table)
                    .col(ClaimSchema::Key)
                    .col(ClaimSchema::CredentialSchemaId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("index-Claim-Path-CredentialId-Unique")
                    .unique()
                    .table(Claim::Table)
                    .col(Claim::Path)
                    .col(Claim::CredentialId)
                    .to_owned(),
            )
            .await?;

        reorder_duplicate_claim_schemas(manager).await?;
        manager
            .create_index(
                Index::create()
                    .name("index-ClaimSchema-Order-CredentialSchemaId-Unique")
                    .unique()
                    .table(ClaimSchema::Table)
                    .col(ClaimSchema::Order)
                    .col(ClaimSchema::CredentialSchemaId)
                    .to_owned(),
            )
            .await?;

        add_nullable_unique_idx(
            CredentialSchemaFormatClaimSchema::Table,
            CredentialSchemaFormatClaimSchema::Namespace,
            "index-FormatClaimSchema-TechKey-FormatId-Namespace-Unique",
            NullableIdxOpts {
                non_nullable_columns: vec![
                    CredentialSchemaFormatClaimSchema::TechnicalKey,
                    CredentialSchemaFormatClaimSchema::CredentialSchemaFormatId,
                ],
                null_value: Some(""),
                materialized_column_size_limit: Some(255),
                ..Default::default()
            },
            manager,
        )
        .await?;

        Ok(())
    }
}

async fn reorder_duplicate_claim_schemas(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let duplicates = find_duplicate_orders(manager).await?;
    for duplicate in duplicates {
        resolve_duplicate_order(manager, duplicate).await?;
    }

    Ok(())
}

#[derive(FromQueryResult, Debug)]
struct DuplicateOrder {
    order: i32,
    credential_schema_id: String,
    occurences: i32,
}

async fn find_duplicate_orders(manager: &SchemaManager<'_>) -> Result<Vec<DuplicateOrder>, DbErr> {
    // SELECT `order`, credential_schema_id, COUNT(*) as occurences
    // FROM claim_schema
    // GROUP BY `order`, credential_schema_id
    // HAVING COUNT(*) > 1;

    let count_all = Func::count(Asterisk.into_column_ref());
    let duplicates = DuplicateOrder::find_by_statement(
        manager.get_database_backend().build(
            Query::select()
                .expr_as(count_all.clone(), "occurences")
                .column(ClaimSchema::Order)
                .column(ClaimSchema::CredentialSchemaId)
                .from(ClaimSchema::Table)
                .group_by_columns([ClaimSchema::Order, ClaimSchema::CredentialSchemaId])
                .cond_having(count_all.gt(1)),
        ),
    )
    .all(manager.get_connection())
    .await?;

    Ok(duplicates)
}

async fn resolve_duplicate_order(
    manager: &SchemaManager<'_>,
    duplicate: DuplicateOrder,
) -> Result<(), DbErr> {
    tracing::debug!(
        "Resolving duplicate order: schema:{}, order:{}, duplicates:{}",
        duplicate.credential_schema_id,
        duplicate.order,
        duplicate.occurences
    );

    let connection = manager.get_connection();

    let mut max_order: i32 = connection
        .query_one(
            Query::select()
                .expr(Func::max(Expr::col(ClaimSchema::Order)))
                .from(ClaimSchema::Table)
                .cond_where(
                    Expr::col(ClaimSchema::CredentialSchemaId).eq(&duplicate.credential_schema_id),
                ),
        )
        .await?
        .ok_or(DbErr::Custom("Could not find max order".to_string()))?
        .try_get_by_index(0)?;

    // IDs of duplicit claim schemas
    let mut entries = connection
        .query_all(
            Query::select()
                .column(ClaimSchema::Id)
                .from(ClaimSchema::Table)
                .cond_where(
                    Expr::col(ClaimSchema::CredentialSchemaId).eq(&duplicate.credential_schema_id),
                )
                .and_where(Expr::col(ClaimSchema::Order).eq(duplicate.order))
                .order_by(ClaimSchema::CreatedDate, Order::Desc),
        )
        .await?;

    // retain order of the oldest entry
    entries.pop();

    // renumber rest of the entries
    for entry in entries {
        max_order += 1;

        let id: String = entry.try_get_by_index(0)?;

        manager
            .exec_stmt(
                Query::update()
                    .table(ClaimSchema::Table)
                    .value(ClaimSchema::Order, max_order)
                    .cond_where(Expr::col(ClaimSchema::Id).eq(id))
                    .to_owned(),
            )
            .await?;
    }

    Ok(())
}
