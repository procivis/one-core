use std::env;

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
        let core_base_url = env::var("MIGRATION_CORE_URL").unwrap_or_default();

        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column(
                        ColumnDef::new(CredentialSchema::ImportedSourceUrl)
                            .string()
                            .not_null()
                            .default(Expr::val("DEFAULT_VALUE")),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ProofSchema::Table)
                    .add_column(
                        ColumnDef::new(ProofSchema::ImportedSourceUrl)
                            .string()
                            .not_null()
                            .default(Expr::val("DEFAULT_VALUE")),
                    )
                    .to_owned(),
            )
            .await?;

        let credential_schema_query = format!(
            "UPDATE {} SET {} = CONCAT('{}', '/ssi/schema/v1/', {})",
            CredentialSchema::Table.to_string(),
            CredentialSchema::ImportedSourceUrl.to_string(),
            core_base_url,
            CredentialSchema::Id.to_string(),
        );

        let proof_schema_query = format!(
            "UPDATE {} SET {} = CONCAT('{}', '/ssi/proof-schema/v1/', {})",
            ProofSchema::Table.to_string(),
            ProofSchema::ImportedSourceUrl.to_string(),
            core_base_url,
            ProofSchema::Id.to_string(),
        );

        manager
            .get_connection()
            .execute_unprepared(&credential_schema_query)
            .await?;
        manager
            .get_connection()
            .execute_unprepared(&proof_schema_query)
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum CredentialSchema {
    Table,
    Id,
    ImportedSourceUrl,
}

#[derive(Iden)]
pub enum ProofSchema {
    Table,
    Id,
    ImportedSourceUrl,
}
