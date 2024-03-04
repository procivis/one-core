use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(CredentialSchema::WalletStorageType)
                            .enumeration(
                                WalletStorageType::Table,
                                [WalletStorageType::Hardware, WalletStorageType::Software],
                            )
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .drop_column(CredentialSchema::WalletStorageType)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum CredentialSchema {
    Table,
    WalletStorageType,
}

#[derive(Iden)]
enum WalletStorageType {
    Table,
    #[iden = "HARDWARE"]
    Hardware,
    #[iden = "SOFTWARE"]
    Software,
}
