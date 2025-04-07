use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Did::Table)
                    .add_column(ColumnDef::new(Did::Log).text().null())
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Did {
    Table,
    Log,
}
