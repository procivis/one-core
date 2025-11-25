use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(History::Table)
                    .add_column(
                        ColumnDef::new(History::Source)
                            .to_owned()
                            .string()
                            .not_null()
                            .default("CORE"),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum History {
    Table,
    Source,
}
