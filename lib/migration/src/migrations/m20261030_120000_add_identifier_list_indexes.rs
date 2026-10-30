use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::Identifier;

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX_IDENTIFIER_ORGANISATION_ID_CREATED_DATE_ID_DELETED_AT: &str =
    "index-Identifier-OrganisationId-CreatedDate-Id-DeletedAt";
const INDEX_IDENTIFIER_KEY_ID: &str = "index-Identifier-KeyId";

// Listing the identifiers of an organisation (default order: newest first) can walk the index and
// stop at the page limit, and the trailing `deleted_at` makes the count an index-only scan.
// Also adds the missing FK child column index on `key_id`, as Postgres and SQLite do not
// automatically create one.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name(INDEX_IDENTIFIER_ORGANISATION_ID_CREATED_DATE_ID_DELETED_AT)
                    .table(Identifier::Table)
                    .col(Identifier::OrganisationId)
                    .col(Identifier::CreatedDate)
                    .col(Identifier::Id)
                    .col(Identifier::DeletedAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(INDEX_IDENTIFIER_KEY_ID)
                    .table(Identifier::Table)
                    .col(Identifier::KeyId)
                    .to_owned(),
            )
            .await
    }
}
