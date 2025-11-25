use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::RevocationList;
use crate::m20250605_092053_drop_column_issuer_did_id_in_revocation_list::NewRevocationList as RevocationListWithIdentifierId;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UNIQUE_ISSUER_PURPOSE_TYPE_INDEX: &str = "index-IssuerIdentifierId-Purpose-Type-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        if backend == DatabaseBackend::Postgres {
            return Ok(());
        }

        // SQLite structure already correct, adjust mysql
        if backend == DatabaseBackend::MySql {
            manager
                .alter_table(
                    Table::alter()
                        .table(RevocationList::Table)
                        // mark `issuer_identifier_id` as NOT NULL
                        .modify_column(
                            ColumnDef::new(RevocationListWithIdentifierId::IssuerIdentifierId)
                                .char_len(36)
                                .not_null(),
                        )
                        // remove default value from `type`
                        .modify_column(
                            ColumnDef::new(RevocationListWithIdentifierId::Type)
                                .string()
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_ISSUER_PURPOSE_TYPE_INDEX)
                    .unique()
                    .table(RevocationList::Table)
                    .col(RevocationListWithIdentifierId::IssuerIdentifierId)
                    .col(RevocationListWithIdentifierId::Purpose)
                    .col(RevocationListWithIdentifierId::Type)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
