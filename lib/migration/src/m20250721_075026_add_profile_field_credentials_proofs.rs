use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add profile column to credential table
        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(ColumnDef::new(Credential::Profile).string().null())
                    .to_owned(),
            )
            .await?;

        // Add profile column to proof table
        manager
            .alter_table(
                Table::alter()
                    .table(Proof::Table)
                    .add_column(ColumnDef::new(Proof::Profile).string().null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Credential {
    Table,
    Profile,
}

#[derive(DeriveIden)]
enum Proof {
    Table,
    Profile,
}
