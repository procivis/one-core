use crate::m20230530_000001_initial::{ClaimSchema, Datatype};
use crate::sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        if backend == DbBackend::Sqlite {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(ClaimSchema::Table)
                    .modify_column(ColumnDef::new(ClaimSchema::Datatype).string().not_null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        if backend == DbBackend::Sqlite {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(ClaimSchema::Table)
                    .modify_column(
                        ColumnDef::new(ClaimSchema::Datatype)
                            .enumeration(
                                Datatype::Table,
                                [Datatype::String, Datatype::Date, Datatype::Number],
                            )
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
