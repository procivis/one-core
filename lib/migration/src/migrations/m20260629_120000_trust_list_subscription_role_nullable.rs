use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_null, text};

use crate::datatype::{timestamp, timestamp_null, uuid_char};
use crate::migrations::m20260417_150300_initial::{TrustCollection, TrustListSubscription};
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
    let db = manager.get_connection();
    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    manager
        .create_table(
            Table::create()
                .table(TrustListSubscriptionNew::Table)
                .col(uuid_char(TrustListSubscriptionNew::Id).primary_key())
                .col(timestamp(TrustListSubscriptionNew::CreatedDate, manager))
                .col(timestamp(TrustListSubscriptionNew::LastModified, manager))
                .col(timestamp_null(
                    TrustListSubscriptionNew::DeactivatedAt,
                    manager,
                ))
                .col(string_null(TrustListSubscriptionNew::Role))
                .col(string(TrustListSubscriptionNew::Type))
                .col(string(TrustListSubscriptionNew::State))
                .col(string(TrustListSubscriptionNew::Name))
                .col(text(TrustListSubscriptionNew::Reference))
                .col(uuid_char(TrustListSubscriptionNew::TrustCollectionId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_TRUST_LIST_SUBSCRIPTION_COLLECTION)
                        .from_tbl(TrustListSubscriptionNew::Table)
                        .from_col(TrustListSubscriptionNew::TrustCollectionId)
                        .to_tbl(TrustCollection::Table)
                        .to_col(TrustCollection::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        TrustListSubscriptionNew::Id,
        TrustListSubscriptionNew::CreatedDate,
        TrustListSubscriptionNew::LastModified,
        TrustListSubscriptionNew::DeactivatedAt,
        TrustListSubscriptionNew::Role,
        TrustListSubscriptionNew::Type,
        TrustListSubscriptionNew::State,
        TrustListSubscriptionNew::Name,
        TrustListSubscriptionNew::Reference,
        TrustListSubscriptionNew::TrustCollectionId,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(TrustListSubscriptionNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(TrustListSubscription::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(TrustListSubscription::Table).to_owned())
        .await?;
    manager
        .rename_table(
            Table::rename()
                .table(
                    TrustListSubscriptionNew::Table,
                    TrustListSubscription::Table,
                )
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

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

#[derive(Clone, DeriveIden)]
enum TrustListSubscriptionNew {
    #[sea_orm(iden = "trust_list_subscription_new")]
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeactivatedAt,
    Name,
    Role,
    Type,
    State,
    Reference,
    TrustCollectionId,
}

const FK_TRUST_LIST_SUBSCRIPTION_COLLECTION: &str = "fk-TrustListSubscription-TrustCollectionId";

const INDEX_UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_COLLECTION_DEACTIVATED_AT: &str =
    "index-TrustListSubscription-Name-Col-DeactivatedAt-Unique";
const INDEX_UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_COLLECTION_DEACTIVATED_AT: &str =
    "index-TrustListSubscription-Reference-Col-DeactivatedAt-Unique";
