use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        manager
            .create_table(
                Table::create()
                    .table(JsonLdContext::Table)
                    .col(
                        ColumnDef::new(JsonLdContext::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(JsonLdContext::CreatedDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(JsonLdContext::LastModified)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(JsonLdContext::Context)
                            .large_blob(manager)
                            .not_null(),
                    )
                    .col(ColumnDef::new(JsonLdContext::Url).string())
                    .col(
                        ColumnDef::new(JsonLdContext::HitCounter)
                            .unsigned()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum JsonLdContext {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Context,
    Url,
    HitCounter,
}
