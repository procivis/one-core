use crate::m20230530_000001_initial::{
    Credential, CustomDateTime, Did, Key, KeyType, Organisation,
};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Key::Table).to_owned())
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Key::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(KeyNew::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(KeyNew::CreatedDate)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(KeyNew::LastModified)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(ColumnDef::new(KeyNew::Name).string().not_null())
                    .col(ColumnDef::new(KeyNew::PublicKey).string().not_null())
                    .col(ColumnDef::new(KeyNew::PrivateKey).binary().not_null())
                    .col(ColumnDef::new(KeyNew::StorageType).string().not_null())
                    .col(ColumnDef::new(KeyNew::KeyType).string().not_null())
                    .col(ColumnDef::new(KeyNew::CredentialId).char_len(36))
                    .col(
                        ColumnDef::new(KeyNew::OrganisationId)
                            .char_len(36)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-Key-CredentialId")
                            .from_tbl(Key::Table)
                            .from_col(KeyNew::CredentialId)
                            .to_tbl(Credential::Table)
                            .to_col(Credential::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-Key-OrganisationId")
                            .from_tbl(Key::Table)
                            .from_col(KeyNew::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(KeyDid::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(KeyDid::DidId).char_len(36).not_null())
                    .col(ColumnDef::new(KeyDid::KeyId).char_len(36).not_null())
                    .col(
                        ColumnDef::new(KeyDid::Role)
                            .enumeration(
                                KeyRole::Table,
                                [
                                    KeyRole::Authentication,
                                    KeyRole::AssertionMethod,
                                    KeyRole::KeyAgreement,
                                    KeyRole::CapabilityInvocation,
                                    KeyRole::CapabilityDelegation,
                                ],
                            )
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-KeyDid")
                            .col(KeyDid::DidId)
                            .col(KeyDid::KeyId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-KeyDid-DidId")
                            .from_tbl(KeyDid::Table)
                            .from_col(KeyDid::DidId)
                            .to_tbl(Did::Table)
                            .to_col(Did::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-KeyDid-KeyId")
                            .from_tbl(KeyDid::Table)
                            .from_col(KeyDid::KeyId)
                            .to_tbl(Key::Table)
                            .to_col(KeyNew::Id),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(KeyDid::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Key::Table).to_owned())
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Key::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Key::DidId).char_len(36).not_null())
                    .col(
                        ColumnDef::new(Key::CreatedDate)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Key::LastModified)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(ColumnDef::new(Key::PublicKey).string().not_null())
                    .col(ColumnDef::new(Key::PrivateKey).string().not_null())
                    .col(ColumnDef::new(Key::StorageType).string().not_null())
                    .col(
                        ColumnDef::new(Key::KeyType)
                            .enumeration(KeyType::Table, [KeyType::Rsa4096, KeyType::Ed25519])
                            .not_null(),
                    )
                    .col(ColumnDef::new(Key::CredentialId).char_len(36))
                    .primary_key(
                        Index::create()
                            .name("pk-Key")
                            .col(Key::DidId)
                            .col(Key::CreatedDate)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-Key-DidId")
                            .from_tbl(Key::Table)
                            .from_col(Key::DidId)
                            .to_tbl(Did::Table)
                            .to_col(Did::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-Key-CredentialId")
                            .from_tbl(Key::Table)
                            .from_col(Key::CredentialId)
                            .to_tbl(Credential::Table)
                            .to_col(Credential::Id),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum KeyNew {
    Id,
    CreatedDate,
    LastModified,
    Name,
    PublicKey,
    PrivateKey,
    StorageType,
    KeyType,
    CredentialId,
    OrganisationId,
}

#[derive(Iden)]
pub enum KeyDid {
    Table,
    KeyId,
    DidId,
    Role,
}

#[derive(Iden)]
pub enum KeyRole {
    Table,
    #[iden = "AUTHENTICATION"]
    Authentication,
    #[iden = "ASSERTION_METHOD"]
    AssertionMethod,
    #[iden = "KEY_AGREEMENT"]
    KeyAgreement,
    #[iden = "CAPABILITY_INVOCATION"]
    CapabilityInvocation,
    #[iden = "CAPABILITY_DELEGATION"]
    CapabilityDelegation,
}
