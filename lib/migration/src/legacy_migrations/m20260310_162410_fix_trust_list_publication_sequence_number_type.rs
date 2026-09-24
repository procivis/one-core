use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

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
                            .table(TrustListPublication::Table)
                            .modify_column(big_integer(TrustListPublication::SequenceNumber))
                            .to_owned(),
                    )
                    .await?;
            }
            DbBackend::Sqlite | DbBackend::Postgres => {}
            other => {
                return Err(DbErr::BackendNotSupported {
                    db: other.as_str(),
                    ctx: "migration",
                });
            }
        }
        Ok(())
    }
}

#[derive(DeriveIden)]
enum TrustListPublication {
    Table,
    SequenceNumber,
}
