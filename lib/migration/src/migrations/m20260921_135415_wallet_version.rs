use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::migrations::m20260720_091548_instance::ManagedInstance;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ManagedInstance::Table)
                    .add_column(string_null(ManagedInstanceWithVersion::Version))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum ManagedInstanceWithVersion {
    Version,
}
