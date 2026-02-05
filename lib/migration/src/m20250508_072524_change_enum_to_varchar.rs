use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

// In the scope of this migration is to change all enum types into string types as they are unsortable

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Credential::Table)
                            .modify_column(ColumnDef::new(Credential::Role).string())
                            .modify_column(ColumnDef::new(Credential::State).string())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(CredentialSchema::Table)
                            .modify_column(ColumnDef::new(CredentialSchema::LayoutType).string())
                            .modify_column(
                                ColumnDef::new(CredentialSchema::WalletStorageType).string(),
                            )
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(Did::Table)
                            .modify_column(ColumnDef::new(Did::Type).string())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(History::Table)
                            .modify_column(ColumnDef::new(History::Action).string())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(Identifier::Table)
                            .modify_column(ColumnDef::new(Identifier::Type).string())
                            .modify_column(ColumnDef::new(Identifier::Status).string())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(KeyDid::Table)
                            .modify_column(ColumnDef::new(KeyDid::Role).string())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(Proof::Table)
                            .modify_column(ColumnDef::new(Proof::State).string())
                            .modify_column(ColumnDef::new(Proof::Role).string())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(RemoteEntityCache::Table)
                            .modify_column(ColumnDef::new(RemoteEntityCache::Type).string())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(RevocationList::Table)
                            .modify_column(ColumnDef::new(RevocationList::Format).string())
                            .modify_column(ColumnDef::new(RevocationList::Purpose).string())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(TrustEntity::Table)
                            .modify_column(ColumnDef::new(TrustEntity::State).string())
                            .modify_column(ColumnDef::new(TrustEntity::Role).string())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(ValidityCredential::Table)
                            .modify_column(ColumnDef::new(ValidityCredential::Type).string())
                            .to_owned(),
                    )
                    .await?;
            }
            DbBackend::Sqlite | DbBackend::Postgres => {}
        }
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Did {
    Table,
    Type,
}

#[derive(DeriveIden)]
enum Credential {
    Table,
    Role,
    State,
}

#[derive(DeriveIden)]
enum CredentialSchema {
    Table,
    WalletStorageType,
    LayoutType,
}

#[derive(DeriveIden)]
enum History {
    Table,
    Action,
}

#[derive(DeriveIden)]
enum Identifier {
    Table,
    Type,
    Status,
}

#[derive(DeriveIden)]
enum KeyDid {
    Table,
    Role,
}

#[derive(DeriveIden)]
pub(crate) enum Proof {
    Table,
    State,
    Role,
}

#[derive(DeriveIden)]
enum RemoteEntityCache {
    Table,
    Type,
}

#[derive(DeriveIden)]
enum RevocationList {
    Table,
    Purpose,
    Format,
}

#[derive(DeriveIden)]
enum TrustEntity {
    Table,
    Role,
    State,
}

#[derive(DeriveIden)]
enum ValidityCredential {
    Table,
    Type,
}
