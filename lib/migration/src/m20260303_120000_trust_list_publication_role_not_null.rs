use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::uuid_char;

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
                            .modify_column(
                                ColumnDef::new(TrustListPublication::Role)
                                    .string()
                                    .not_null(),
                            )
                            .modify_column(
                                uuid_char(TrustListPublication::OrganisationId).not_null(),
                            )
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
enum TrustListPublication {
    Table,
    Role,
    OrganisationId,
}
