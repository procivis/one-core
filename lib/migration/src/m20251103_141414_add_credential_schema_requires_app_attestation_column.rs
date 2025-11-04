use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

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
                    .add_column_if_not_exists(
                        boolean(CredentialSchema::RequiresAppAttestation)
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(CredentialSchema::Table)
                    .value(CredentialSchema::WalletStorageType, "HARDWARE")
                    .value(CredentialSchema::RequiresAppAttestation, true)
                    .cond_where(
                        Expr::col((CredentialSchema::Table, CredentialSchema::WalletStorageType))
                            .eq("EUDI_COMPLIANT"),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum CredentialSchema {
    Table,
    WalletStorageType,
    RequiresAppAttestation,
}
