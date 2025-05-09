use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Credential::Table)
                            .modify_column(ColumnDef::new(Credential::Role).string().not_null())
                            .modify_column(ColumnDef::new(Credential::State).string().not_null())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(CredentialSchema::Table)
                            .modify_column(
                                ColumnDef::new(CredentialSchema::LayoutType)
                                    .string()
                                    .not_null(),
                            )
                            .modify_column(
                                ColumnDef::new(CredentialSchema::WalletStorageType)
                                    .string()
                                    .null(),
                            )
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(Did::Table)
                            .modify_column(ColumnDef::new(Did::Type).string().not_null())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(History::Table)
                            .modify_column(ColumnDef::new(History::Action).string().not_null())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(Identifier::Table)
                            .modify_column(ColumnDef::new(Identifier::Type).string().not_null())
                            .modify_column(ColumnDef::new(Identifier::Status).string().not_null())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(KeyDid::Table)
                            .modify_column(ColumnDef::new(KeyDid::Role).string().not_null())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(Proof::Table)
                            .modify_column(ColumnDef::new(Proof::State).string().not_null())
                            .modify_column(ColumnDef::new(Proof::Role).string().not_null())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(RemoteEntityCache::Table)
                            .modify_column(
                                ColumnDef::new(RemoteEntityCache::Type).string().not_null(),
                            )
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(RevocationList::Table)
                            .modify_column(
                                ColumnDef::new(RevocationList::Format).string().not_null(),
                            )
                            .modify_column(
                                ColumnDef::new(RevocationList::Purpose).string().not_null(),
                            )
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(TrustEntity::Table)
                            .modify_column(ColumnDef::new(TrustEntity::State).string().not_null())
                            .modify_column(ColumnDef::new(TrustEntity::Role).string().not_null())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(ValidityCredential::Table)
                            .modify_column(
                                ColumnDef::new(ValidityCredential::Type).string().not_null(),
                            )
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
enum Proof {
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
