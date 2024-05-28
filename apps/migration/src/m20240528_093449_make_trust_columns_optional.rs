use sea_orm_migration::prelude::*;

use crate::m20240514_070446_add_trust_model::TrustAnchor;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(TrustAnchor::Table)
                    .drop_column(TrustAnchor::PublisherReference)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(TrustAnchor::Table)
                    .add_column(ColumnDef::new(TrustAnchor::PublisherReference).string())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(TrustAnchor::Table)
                    .drop_column(TrustAnchor::Priority)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(TrustAnchor::Table)
                    .add_column(ColumnDef::new(TrustAnchor::Priority).unsigned())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, _: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration("One way migration".to_owned()))
    }
}
