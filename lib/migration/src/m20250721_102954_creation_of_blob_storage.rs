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
                    .table(BlobStorage::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(BlobStorage::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(BlobStorage::CreatedDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BlobStorage::LastModified)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BlobStorage::Value)
                            .large_blob(manager)
                            .not_null(),
                    )
                    .col(ColumnDef::new(BlobStorage::Type).text().not_null())
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum BlobStorage {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Value,
    Type,
}
