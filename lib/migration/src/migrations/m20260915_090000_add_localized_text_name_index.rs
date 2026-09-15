use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::migrations::m20260512_062412_localized_text::LocalizedText;

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX_LOCALIZED_TEXT_ENTITY_TYPE_FIELD_LANG_VALUE: &str =
    "index-LocalizedText-EntityType-Field-Lang-Value";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut index = Index::create()
            .name(INDEX_LOCALIZED_TEXT_ENTITY_TYPE_FIELD_LANG_VALUE)
            .table(LocalizedText::Table)
            .to_owned();

        if manager.get_database_backend() == DbBackend::MySql {
            // MariaDB limits an index to 3072 bytes. The three string columns
            // default to VARCHAR(255), while value is TEXT, so indexing the
            // complete columns exceeds that limit. Prefixes are sufficient for
            // this non-unique lookup index; the full predicates are still
            // evaluated by the query.
            index
                .col((LocalizedText::EntityType, 16))
                .col((LocalizedText::Field, 16))
                .col((LocalizedText::Lang, 32))
                .col((LocalizedText::Value, 512));
        } else {
            index
                .col(LocalizedText::EntityType)
                .col(LocalizedText::Field)
                .col(LocalizedText::Lang)
                .col(LocalizedText::Value);
        }

        manager.create_index(index).await
    }
}
