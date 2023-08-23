use crate::m20230530_000001_initial::{
    Credential, CredentialSchema, Did, DidMethod, Format, Key, RevocationMethod, StorageType,
    Transport,
};
use crate::sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        if backend == DbBackend::Sqlite {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .modify_column(ColumnDef::new(CredentialSchema::Format).string().not_null())
                    .modify_column(
                        ColumnDef::new(CredentialSchema::RevocationMethod)
                            .string()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Did::Table)
                    .modify_column(ColumnDef::new(Did::Method).string().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .modify_column(ColumnDef::new(Credential::Transport).string().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Key::Table)
                    .modify_column(ColumnDef::new(Key::StorageType).string().not_null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        if backend == DbBackend::Sqlite {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .modify_column(
                        ColumnDef::new(CredentialSchema::Format)
                            .enumeration(
                                Format::Table,
                                [Format::Jwt, Format::SdJwt, Format::JsonLd, Format::Mdoc],
                            )
                            .not_null(),
                    )
                    .modify_column(
                        ColumnDef::new(CredentialSchema::RevocationMethod)
                            .enumeration(
                                RevocationMethod::Table,
                                [
                                    RevocationMethod::None,
                                    RevocationMethod::StatusList2021,
                                    RevocationMethod::Lvvc,
                                ],
                            )
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Did::Table)
                    .modify_column(
                        ColumnDef::new(Did::Method)
                            .enumeration(DidMethod::Table, [DidMethod::Key, DidMethod::Web])
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .modify_column(
                        ColumnDef::new(Credential::Transport)
                            .enumeration(
                                Transport::Table,
                                [Transport::ProcivisTemporary, Transport::OpenId4Vc],
                            )
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Key::Table)
                    .modify_column(
                        ColumnDef::new(Key::StorageType)
                            .enumeration(
                                StorageType::Table,
                                [
                                    StorageType::Intern,
                                    StorageType::Extern,
                                    StorageType::InternHsm,
                                ],
                            )
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
