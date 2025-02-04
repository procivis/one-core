use sea_orm::{DatabaseBackend, DbBackend, EnumIter, Iterable};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(CredentialSchema::Table)
                            .modify_column(
                                ColumnDef::new(CredentialSchema::WalletStorageType).enumeration(
                                    CredentialSchema::Table,
                                    WalletStorageType::iter(),
                                ),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            // we don't need to change enums for sqlite since they are stored as TEXT
            DatabaseBackend::Sqlite => {}
            // Postgres not supported at the moment, adding this as a reference.
            DbBackend::Postgres => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(CredentialSchema::Table)
                            .modify_column(
                                ColumnDef::new(CredentialSchema::WalletStorageType)
                                    .enumeration(CredentialSchema::Table, WalletStorageType::iter())
                                    .extra("ADD VALUE 'REMOTE_SECURE_ELEMENT'"),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
        };
        Ok(())
    }
}

#[derive(DeriveIden)]
enum CredentialSchema {
    Table,
    WalletStorageType,
}

#[derive(DeriveIden, EnumIter)]
pub enum WalletStorageType {
    #[sea_orm(iden = "HARDWARE")]
    Hardware,
    #[sea_orm(iden = "SOFTWARE")]
    Software,
    #[sea_orm(iden = "REMOTE_SECURE_ELEMENT")]
    RemoteSecureElement,
}
