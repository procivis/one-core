use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::datatype::uuid_char;
use crate::m20240110_000001_initial::Organisation;
use crate::soft_delete_unique_idx::{Params, add_soft_delete_unique_idx};

pub(crate) const UNIQUE_TRUST_COLLECTION_NAME_DEACTIVATED_AT_INDEX: &str =
    "index-TrustCollection-Name-DeactivatedAt-Unique";
pub(crate) const UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_DEACTIVATED_AT_INDEX: &str =
    "index-TrustListSubscription-Name-DeactivatedAt-Unique";
pub(crate) const UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_DEACTIVATED_AT_INDEX: &str =
    "index-TrustListSubscription-Reference-DeactivatedAt-Unique";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .create_table(
                Table::create()
                    .table(TrustCollection::Table)
                    .col(uuid_char(TrustCollection::Id).primary_key())
                    .col(crate::datatype::timestamp(
                        TrustCollection::CreatedDate,
                        manager,
                    ))
                    .col(crate::datatype::timestamp(
                        TrustCollection::LastModified,
                        manager,
                    ))
                    .col(crate::datatype::timestamp_null(
                        TrustCollection::DeactivatedAt,
                        manager,
                    ))
                    .col(string(TrustCollection::Name))
                    .col(uuid_char(TrustCollection::OrganisationId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-TrustCollection-OrganisationId")
                            .from_tbl(TrustCollection::Table)
                            .from_col(TrustCollection::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        add_soft_delete_unique_idx(
            Params {
                table: TrustCollection::Table.to_string(),
                columns: vec![TrustCollection::Name.to_string()],
                soft_delete_column: TrustCollection::DeactivatedAt.to_string(),
                index_name: UNIQUE_TRUST_COLLECTION_NAME_DEACTIVATED_AT_INDEX.to_owned(),
            },
            manager,
        )
        .await?;

        manager
            .create_table(
                Table::create()
                    .table(TrustListSubscription::Table)
                    .col(uuid_char(TrustListSubscription::Id).primary_key())
                    .col(crate::datatype::timestamp(
                        TrustListSubscription::CreatedDate,
                        manager,
                    ))
                    .col(crate::datatype::timestamp(
                        TrustListSubscription::LastModified,
                        manager,
                    ))
                    .col(crate::datatype::timestamp_null(
                        TrustListSubscription::DeactivatedAt,
                        manager,
                    ))
                    .col(string(TrustListSubscription::Name))
                    .col(string(TrustListSubscription::Role))
                    .col(string(TrustListSubscription::Type))
                    .col(string(TrustListSubscription::State))
                    .col(text(TrustListSubscription::Reference))
                    .col(uuid_char(TrustListSubscription::TrustCollectionId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-TrustListSubscription-TrustCollectionId")
                            .from_tbl(TrustListSubscription::Table)
                            .from_col(TrustListSubscription::TrustCollectionId)
                            .to_tbl(TrustCollection::Table)
                            .to_col(TrustCollection::Id),
                    )
                    .to_owned(),
            )
            .await?;

        add_soft_delete_unique_idx(
            Params {
                table: TrustListSubscription::Table.to_string(),
                columns: vec![TrustListSubscription::Name.to_string()],
                soft_delete_column: TrustListSubscription::DeactivatedAt.to_string(),
                index_name: UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_DEACTIVATED_AT_INDEX.to_owned(),
            },
            manager,
        )
        .await?;
        add_soft_delete_unique_idx(
            Params {
                table: TrustListSubscription::Table.to_string(),
                columns: vec![TrustListSubscription::Reference.to_string()],
                soft_delete_column: TrustListSubscription::DeactivatedAt.to_string(),
                index_name: UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_DEACTIVATED_AT_INDEX
                    .to_owned(),
            },
            manager,
        )
        .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum TrustCollection {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeactivatedAt,
    Name,
    OrganisationId,
}

#[derive(DeriveIden)]
pub enum TrustListSubscription {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeactivatedAt,
    Name,
    Role,
    Type,
    Reference,
    State,
    TrustCollectionId,
}
