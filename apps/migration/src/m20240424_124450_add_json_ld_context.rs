use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::CustomDateTime;
use crate::ColumnDefExt;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let datetime = CustomDateTime(manager.get_database_backend());

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
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(JsonLdContext::LastModified)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(JsonLdContext::Context)
                            .custom_blob(manager)
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

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(JsonLdContext::Table).to_owned())
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
