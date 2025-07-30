use sea_orm::{EnumIter, Iterable};
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
                    .table(ValidityCredential::Table)
                    .add_column(
                        ColumnDef::new(ValidityCredential::Type)
                            .enumeration(ValidityCredentialTypeEnum, ValidityCredentialType::iter())
                            .not_null()
                            .default(ValidityCredentialType::Lvvc.to_string()),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ValidityCredential {
    Table,
    Type,
}

#[derive(Iden)]
struct ValidityCredentialTypeEnum;

#[derive(Iden, EnumIter)]
enum ValidityCredentialType {
    #[iden = "LVVC"]
    Lvvc,
    #[iden = "MDOC"]
    Mdoc,
}
