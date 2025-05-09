use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(History::Table)
                            .modify_column(ColumnDef::new(History::EntityType).string().not_null())
                            .to_owned(),
                    )
                    .await?;
            }
            DbBackend::Sqlite | DbBackend::Postgres => {}
        }
        Ok(())
    }
}

#[derive(DeriveIden)]
enum History {
    Table,
    EntityType,
}
