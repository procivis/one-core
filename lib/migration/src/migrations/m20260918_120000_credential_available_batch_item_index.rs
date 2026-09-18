use sea_orm::sea_query::IndexOrder;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("index-Credential-EarliestExpiringBatchItem")
                    .table(Credential::Table)
                    // This prefix also covers the existing consumed-at index and
                    // the query for parents with accepted, unconsumed items.
                    .col(Credential::ConsumedAt)
                    .col(Credential::State)
                    .col(Credential::ParentId)
                    .col(Credential::Format)
                    .col(Credential::Type)
                    .col(Credential::DeletedAt)
                    // Support the earliest-expiring available item query and its ID tie-breaker.
                    .col((Credential::ExpiresAt, IndexOrder::Asc))
                    .col((Credential::Id, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("index-Credential-ConsumedAt")
                    .table(Credential::Table)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Credential {
    Table,
    Id,
    ExpiresAt,
    DeletedAt,
    ConsumedAt,
    State,
    ParentId,
    Format,
    Type,
}
