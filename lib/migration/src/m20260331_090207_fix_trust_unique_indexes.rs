use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::m20260302_170000_trust_list_publication::TrustListPublication;
use crate::m20260302_170100_trust_entry::TrustEntry;
use crate::m20260316_143109_trust_collection_subscription::{
    TrustCollection, TrustListSubscription, UNIQUE_TRUST_COLLECTION_NAME_DEACTIVATED_AT_INDEX,
    UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_DEACTIVATED_AT_INDEX,
    UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_DEACTIVATED_AT_INDEX,
};
use crate::soft_delete_unique_idx::{Params, add_soft_delete_unique_idx};

#[derive(DeriveMigrationName)]
pub struct Migration;

const UNIQUE_TRUST_COLLECTION_NAME_ORG_DEACTIVATED_AT_INDEX: &str =
    "index-TrustCol-Name-Org-DeactivatedAt-Unique";
const UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_COLLECTION_DEACTIVATED_AT_INDEX: &str =
    "index-TrustListSubscription-Name-Col-DeactivatedAt-Unique";
const UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_COLLECTION_DEACTIVATED_AT_INDEX: &str =
    "index-TrustListSubscription-Reference-Col-DeactivatedAt-Unique";
const UNIQUE_TRUST_PUBLICATION_NAME_ORG_DEACTIVATED_AT_INDEX: &str =
    "index-TrustPublication-Name-Org-DeactivatedAt-Unique";
const UNIQUE_TRUST_ENTRY_IDENTIFIER_PUBLICATION_INDEX: &str =
    "index-TrustEntry-IdentifierId-Publication-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Postgres {
            return Ok(());
        }

        // Delete all trust entries and publications, because uniqueness is already violated
        manager
            .exec_stmt(Query::delete().from_table(TrustEntry::Table).to_owned())
            .await?;
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(TrustListPublication::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(UNIQUE_TRUST_COLLECTION_NAME_DEACTIVATED_AT_INDEX)
                    .table(TrustCollection::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_DEACTIVATED_AT_INDEX)
                    .table(TrustListSubscription::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name(UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_DEACTIVATED_AT_INDEX)
                    .table(TrustListSubscription::Table)
                    .to_owned(),
            )
            .await?;

        add_soft_delete_unique_idx(
            Params {
                table: TrustCollection::Table.to_string(),
                columns: vec![
                    TrustCollection::Name.to_string(),
                    TrustCollection::OrganisationId.to_string(),
                ],
                soft_delete_column: TrustCollection::DeactivatedAt.to_string(),
                index_name: UNIQUE_TRUST_COLLECTION_NAME_ORG_DEACTIVATED_AT_INDEX.to_owned(),
            },
            manager,
        )
        .await?;
        add_soft_delete_unique_idx(
            Params {
                table: TrustListSubscription::Table.to_string(),
                columns: vec![
                    TrustListSubscription::Name.to_string(),
                    TrustListSubscription::TrustCollectionId.to_string(),
                ],
                soft_delete_column: TrustListSubscription::DeactivatedAt.to_string(),
                index_name: UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_COLLECTION_DEACTIVATED_AT_INDEX
                    .to_owned(),
            },
            manager,
        )
        .await?;
        add_soft_delete_unique_idx(
            Params {
                table: TrustListSubscription::Table.to_string(),
                columns: vec![
                    TrustListSubscription::Reference.to_string(),
                    TrustListSubscription::TrustCollectionId.to_string(),
                ],
                soft_delete_column: TrustListSubscription::DeactivatedAt.to_string(),
                index_name:
                    UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_COLLECTION_DEACTIVATED_AT_INDEX
                        .to_owned(),
            },
            manager,
        )
        .await?;
        add_soft_delete_unique_idx(
            Params {
                table: TrustListPublication::Table.to_string(),
                columns: vec![
                    TrustListPublication::Name.to_string(),
                    TrustListPublication::OrganisationId.to_string(),
                ],
                soft_delete_column: TrustListPublication::DeactivatedAt.to_string(),
                index_name: UNIQUE_TRUST_PUBLICATION_NAME_ORG_DEACTIVATED_AT_INDEX.to_owned(),
            },
            manager,
        )
        .await?;
        manager
            .create_index(
                Index::create()
                    .unique()
                    .name(UNIQUE_TRUST_ENTRY_IDENTIFIER_PUBLICATION_INDEX)
                    .table(TrustEntry::Table)
                    .col(TrustEntry::IdentifierId)
                    .col(TrustEntry::TrustListPublicationId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
