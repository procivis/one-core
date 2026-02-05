use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Proof::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(Proof::ProofBlobId).char_len(36).null(),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub(crate) enum Proof {
    Table,
    ProofBlobId,
}
