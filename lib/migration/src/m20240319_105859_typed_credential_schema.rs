use std::env;

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

pub const SCHEMA_ID_IN_ORGANISATION_INDEX: &str = "index-SchemaID-Organisation";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        let core_base_url = env::var("MIGRATION_CORE_URL").unwrap_or_default();
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column(
                        ColumnDef::new(CredentialSchema::SchemaType)
                            .string()
                            .not_null()
                            .default(Expr::val("ProcivisOneSchema2024")),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column(
                        ColumnDef::new(CredentialSchema::SchemaId)
                            .string()
                            .not_null()
                            .default(Expr::val("TEMP")),
                    )
                    .to_owned(),
            )
            .await?;

        // Update the Schema ID that way since sqlite doesn't support such an operation on column creation.
        let update_statement = Query::update()
            .table(CredentialSchema::Table)
            .value(
                CredentialSchema::SchemaId,
                Expr::cust(format!("CONCAT('{core_base_url}/ssi/schema/v1/', id);")),
            )
            .to_owned();

        let statement = backend.build(&update_statement);
        db.execute(statement).await?;

        manager
            .create_index(
                Index::create()
                    .unique()
                    .name(SCHEMA_ID_IN_ORGANISATION_INDEX)
                    .table(CredentialSchema::Table)
                    .col(CredentialSchema::OrganisationId)
                    .col(CredentialSchema::SchemaId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum CredentialSchema {
    Table,
    SchemaType,
    SchemaId,
    OrganisationId,
}
