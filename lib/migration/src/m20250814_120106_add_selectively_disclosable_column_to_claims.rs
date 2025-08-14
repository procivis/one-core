use sea_orm_migration::prelude::*;

use crate::m20240611_110000_introduce_path_and_array::Claim;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Claim::Table)
                    .add_column(
                        ColumnDef::new(ClaimNew::SelectivelyDisclosable)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
#[allow(clippy::enum_variant_names, unused)]
pub enum ClaimNew {
    Table,
    SelectivelyDisclosable,
}
