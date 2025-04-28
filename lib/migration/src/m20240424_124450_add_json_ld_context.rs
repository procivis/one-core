use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
