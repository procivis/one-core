use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Postgres {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column(
                        ColumnDef::new(CredentialSchema::KeyStorageSecurity)
                            .string()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(CredentialSchema::Table)
                    .value(
                        CredentialSchema::KeyStorageSecurity,
                        Expr::case(
                            Expr::column(CredentialSchema::WalletStorageType)
                                .eq(Expr::val("HARDWARE")),
                            Expr::val("MODERATE"),
                        )
                        .case(
                            Expr::column(CredentialSchema::WalletStorageType)
                                .eq(Expr::val("REMOTE_SECURE_ELEMENT")),
                            Expr::val("HIGH"),
                        )
                        // Anything unknown and SOFTWARE will be set to null
                        .finally(Expr::val(Value::String(None))),
                    )
                    .to_owned(),
            )
            .await?;

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
    KeyStorageSecurity,
}
