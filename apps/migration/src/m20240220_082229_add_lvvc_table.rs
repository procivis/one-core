use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{Credential, CustomDateTime};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let datetime = CustomDateTime(manager.get_database_backend());

        manager
            .create_table(
                Table::create()
                    .table(Lvvc::Table)
                    .col(
                        ColumnDef::new(Lvvc::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Lvvc::CreatedDate)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Lvvc::Credential)
                            .blob(BlobSize::Long)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Lvvc::CredentialId).char_len(36).not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-Lvvc-CredentialId")
                            .from_tbl(Lvvc::Table)
                            .from_col(Lvvc::CredentialId)
                            .to_tbl(Credential::Table)
                            .to_col(Credential::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Lvvc::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Lvvc {
    Table,
    Id,
    CreatedDate,
    Credential,
    CredentialId,
}
