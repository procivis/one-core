use sea_orm_migration::prelude::*;

use crate::datatype::large_blob_null;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(RevocationList::Table)
                    .add_column(large_blob_null(RevocationList::Params, manager))
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum RevocationList {
    Table,
    Params,
}
