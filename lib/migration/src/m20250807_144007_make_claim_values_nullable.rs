use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::Claim;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => Ok(()),
            DbBackend::Sqlite => sqlite_migration(manager).await,
            DbBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Claim::Table)
                            .modify_column(ColumnDef::new(Claim::Value).large_blob(manager).null())
                            .to_owned(),
                    )
                    .await
            }
        }
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Claim::Table)
                .add_column(
                    ColumnDef::new(ClaimCopy::ValueCopy)
                        .large_blob(manager)
                        .null(),
                )
                .to_owned(),
        )
        .await?;
    manager
        .exec_stmt(
            Query::update()
                .table(Claim::Table)
                .value(
                    ClaimCopy::ValueCopy,
                    SimpleExpr::Column(Claim::Value.into_column_ref()),
                )
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(Claim::Table)
                .drop_column(Claim::Value)
                .to_owned(),
        )
        .await?;
    manager
        .alter_table(
            Table::alter()
                .table(Claim::Table)
                .rename_column(ClaimCopy::ValueCopy, Claim::Value)
                .to_owned(),
        )
        .await
}

#[derive(Iden)]
pub enum ClaimCopy {
    ValueCopy,
}
