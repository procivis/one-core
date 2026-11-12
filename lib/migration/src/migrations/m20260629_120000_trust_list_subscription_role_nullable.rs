use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::string_null;
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::migrations::m20260417_150300_initial::TrustListSubscription;
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.supported_db_type() {
            SupportedDbType::Sqlite => alter_trust_list_subscription_sqlite(manager).await,
            r#type @ (SupportedDbType::MySql | SupportedDbType::Postgres) => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(TrustListSubscription::Table)
                            .modify_column(string_null(TrustListSubscription::Role))
                            .to_owned(),
                    )
                    .await?;
                if r#type == SupportedDbType::MySql {
                    manager
                        .get_connection()
                        .execute_unprepared(
                            "ALTER TABLE `trust_list_subscription` ALTER COLUMN `role` DROP DEFAULT",
                        )
                        .await?;
                }
                Ok(())
            }
        }
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

async fn alter_trust_list_subscription_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .recreate_table(
            Table::recreate()
                .table(TrustListSubscription::Table)
                .modify_column(string_null(TrustListSubscriptionNew::Role))
                .discard_indexes()
                .to_owned(),
        )
        .await?;

    add_nullable_unique_idx(
        TrustListSubscription::Table,
        TrustListSubscription::DeactivatedAt,
        INDEX_UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_COLLECTION_DEACTIVATED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![
                TrustListSubscription::Name,
                TrustListSubscription::TrustCollectionId,
            ],
            null_value: Some("not_deactivated"),
            ..Default::default()
        },
        manager,
    )
    .await?;
    add_nullable_unique_idx(
        TrustListSubscription::Table,
        TrustListSubscription::DeactivatedAt,
        INDEX_UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_COLLECTION_DEACTIVATED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![
                TrustListSubscription::Reference,
                TrustListSubscription::TrustCollectionId,
            ],
            null_value: Some("not_deactivated"),
            ..Default::default()
        },
        manager,
    )
    .await?;

    Ok(())
}

#[derive(Clone, DeriveIden)]
enum TrustListSubscriptionNew {
    Role,
}

const INDEX_UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_COLLECTION_DEACTIVATED_AT: &str =
    "index-TrustListSubscription-Name-Col-DeactivatedAt-Unique";
const INDEX_UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_COLLECTION_DEACTIVATED_AT: &str =
    "index-TrustListSubscription-Reference-Col-DeactivatedAt-Unique";
