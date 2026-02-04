use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres => {}
            DatabaseBackend::MySql | DatabaseBackend::Sqlite => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(CredentialSchema::Table)
                            .add_column(
                                ColumnDef::new(CredentialSchema::TransactionCodeType)
                                    .string()
                                    .null(),
                            )
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(CredentialSchema::Table)
                            .add_column(
                                ColumnDef::new(CredentialSchema::TransactionCodeLength)
                                    .unsigned()
                                    .null(),
                            )
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(CredentialSchema::Table)
                            .add_column(
                                ColumnDef::new(CredentialSchema::TransactionCodeDescription)
                                    .string_len(300)
                                    .null(),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
        };

        Ok(())
    }
}

#[derive(Iden)]
enum CredentialSchema {
    Table,
    TransactionCodeType,
    TransactionCodeLength,
    TransactionCodeDescription,
}
