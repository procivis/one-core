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
        manager
            .alter_table(
                Table::alter()
                    .table(ProofInputClaimSchema::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(ProofInputClaimSchema::Required)
                            .boolean()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[expect(dead_code)]
#[derive(DeriveIden)]
pub enum ProofInputClaimSchema {
    Table,
    ClaimSchemaId,
    ProofInputSchemaId,
    Order,
    Required,
}
