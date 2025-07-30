use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
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
