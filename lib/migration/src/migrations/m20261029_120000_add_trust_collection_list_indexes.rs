use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::{TrustCollection, TrustListSubscription};

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX_TRUST_COLLECTION_ORGANISATION_ID: &str = "index-TrustCollection-OrganisationId";
const INDEX_TRUST_LIST_SUBSCRIPTION_TRUST_COLLECTION_ID_DEACTIVATED_AT: &str =
    "index-TrustListSubscription-TrustCollectionId-DeactivatedAt";

// Adds missing FK child column indexes, as Postgres and SQLite do not automatically create them.
// Used when listing the trust collections of an organisation and filtering by active subscriptions.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name(INDEX_TRUST_COLLECTION_ORGANISATION_ID)
                    .table(TrustCollection::Table)
                    .col(TrustCollection::OrganisationId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(INDEX_TRUST_LIST_SUBSCRIPTION_TRUST_COLLECTION_ID_DEACTIVATED_AT)
                    .table(TrustListSubscription::Table)
                    .col(TrustListSubscription::TrustCollectionId)
                    .col(TrustListSubscription::DeactivatedAt)
                    .to_owned(),
            )
            .await
    }
}
