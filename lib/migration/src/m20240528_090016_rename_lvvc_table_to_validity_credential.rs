use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .rename_table(
                Table::rename()
                    .table(Lvvc::Table, ValidityCredential::Table)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Lvvc {
    Table,
}

#[derive(DeriveIden)]
enum ValidityCredential {
    Table,
}
