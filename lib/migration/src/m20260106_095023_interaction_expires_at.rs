use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::timestamp_null;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Postgres {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(Interaction::Table)
                    .add_column_if_not_exists(timestamp_null(Interaction::ExpiresAt, manager))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Interaction {
    Table,
    ExpiresAt,
}
