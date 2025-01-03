use sea_orm_migration::prelude::*;

use crate::m20240514_070446_add_trust_model::TrustEntity;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(TrustEntity::Table)
                    .drop_column(TrustEntity::Logo)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(TrustEntity::Table)
                    .add_column(ColumnDef::new(TrustEntity::Logo).blob(BlobSize::Long))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, _: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration("One way migration".to_owned()))
    }
}
