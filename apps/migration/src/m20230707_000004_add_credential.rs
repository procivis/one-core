use sea_orm_migration::prelude::*;

use crate::m20230530_000001_initial::{ClaimSchema, CredentialSchema, Organisation, ProofSchema};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Did::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Did::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Did::Did).string().not_null())
                    .col(ColumnDef::new(Did::CreatedDate).date_time().not_null())
                    .col(ColumnDef::new(Did::LastModified).date_time().not_null())
                    .col(ColumnDef::new(Did::Name).string().not_null())
                    .col(
                        ColumnDef::new(Did::Type)
                            .enumeration(DidType::Table, [DidType::Remote, DidType::Local])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Did::Method)
                            .enumeration(DidMethod::Table, [DidMethod::Key, DidMethod::Web])
                            .not_null(),
                    )
                    .col(ColumnDef::new(Did::OrganisationId).char_len(36).not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-Did-OrganisationId")
                            .from_tbl(Did::Table)
                            .from_col(Did::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Credential::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Credential::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Credential::CreatedDate)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Credential::LastModified)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Credential::IssuanceDate)
                            .date_time()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Credential::DeletedAt).date_time().null())
                    .col(
                        ColumnDef::new(Credential::Transport)
                            .enumeration(
                                Transport::Table,
                                [Transport::ProcivisTemporary, Transport::OpenId4Vc],
                            )
                            .not_null(),
                    )
                    .col(ColumnDef::new(Credential::Credential).binary().not_null())
                    .col(
                        ColumnDef::new(Credential::CredentialSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Credential::DidId).string())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-Credential-CredentialSchemaId")
                            .from_tbl(Credential::Table)
                            .from_col(Credential::CredentialSchemaId)
                            .to_tbl(CredentialSchema::Table)
                            .to_col(CredentialSchema::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-Credential-DidId")
                            .from_tbl(Credential::Table)
                            .from_col(Credential::DidId)
                            .to_tbl(Did::Table)
                            .to_col(Did::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CredentialState::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CredentialState::CredentialId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialState::CreatedDate)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialState::State)
                            .enumeration(
                                State::Table,
                                [
                                    State::Created,
                                    State::Pending,
                                    State::Offered,
                                    State::Accepted,
                                    State::Rejected,
                                    State::Revoked,
                                    State::Error,
                                ],
                            )
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-CredentialState")
                            .col(CredentialState::CredentialId)
                            .col(CredentialState::CreatedDate)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-CredentialState-CredentialId")
                            .from_tbl(CredentialState::Table)
                            .from_col(CredentialState::CredentialId)
                            .to_tbl(Credential::Table)
                            .to_col(Credential::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Proof::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Proof::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Proof::CreatedDate).date_time().not_null())
                    .col(ColumnDef::new(Proof::LastModified).date_time().not_null())
                    .col(ColumnDef::new(Proof::IssuanceDate).date_time().not_null())
                    .col(ColumnDef::new(Proof::DidId).string().not_null())
                    .col(ColumnDef::new(Proof::ProofSchemaId).char_len(36).not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-Proof-DidId")
                            .from_tbl(Proof::Table)
                            .from_col(Proof::DidId)
                            .to_tbl(Did::Table)
                            .to_col(Did::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-Proof-ProofSchemaId")
                            .from_tbl(Proof::Table)
                            .from_col(Proof::ProofSchemaId)
                            .to_tbl(ProofSchema::Table)
                            .to_col(ProofSchema::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ProofState::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(ProofState::ProofId).char_len(36).not_null())
                    .col(
                        ColumnDef::new(ProofState::CreatedDate)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofState::LastModified)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofState::State)
                            .enumeration(
                                ProofRequestState::Table,
                                [
                                    ProofRequestState::Created,
                                    ProofRequestState::Pending,
                                    ProofRequestState::Offered,
                                    ProofRequestState::Accepted,
                                    ProofRequestState::Rejected,
                                    ProofRequestState::Error,
                                ],
                            )
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-ProofState")
                            .col(ProofState::ProofId)
                            .col(ProofState::CreatedDate)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ProofState-ProofId")
                            .from_tbl(ProofState::Table)
                            .from_col(ProofState::ProofId)
                            .to_tbl(Proof::Table)
                            .to_col(Proof::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Claim::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Claim::ClaimSchemaId).char_len(36).not_null())
                    .col(ColumnDef::new(Claim::CredentialId).char_len(36).not_null())
                    //.col(ColumnDef::new(Claim::ProofId).char_len(36).not_null())
                    .col(ColumnDef::new(Claim::Value).string().not_null())
                    .col(ColumnDef::new(Claim::CreatedDate).date_time().not_null())
                    .col(ColumnDef::new(Claim::LastModified).date_time().not_null())
                    .primary_key(
                        Index::create()
                            .name("pk-Claim")
                            .col(Claim::ClaimSchemaId)
                            .col(Claim::CredentialId)
                            // .col(Claim::ProofId)
                            .col(Claim::Value)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-Claim-ClaimSchemaId")
                            .from_tbl(Claim::Table)
                            .from_col(Claim::ClaimSchemaId)
                            .to_tbl(ClaimSchema::Table)
                            .to_col(ClaimSchema::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-Claim-CredentialId")
                            .from_tbl(Claim::Table)
                            .from_col(Claim::CredentialId)
                            .to_tbl(Credential::Table)
                            .to_col(Credential::Id),
                    )
                    // .foreign_key(
                    //     ForeignKeyCreateStatement::new()
                    //         .name("fk-Claim-ProofId")
                    //         .from_tbl(Claim::Table)
                    //         .from_col(Claim::ProofId)
                    //         .to_tbl(Proof::Table)
                    //         .to_col(Proof::Id),
                    // )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Key::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Key::DidId).char_len(36).not_null())
                    .col(ColumnDef::new(Key::CreatedDate).date_time().not_null())
                    .col(ColumnDef::new(Key::LastModified).date_time().not_null())
                    .col(ColumnDef::new(Key::PublicKey).string().not_null())
                    .col(ColumnDef::new(Key::PrivateKey).string().not_null())
                    .col(
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
                    .col(
                        ColumnDef::new(Key::KeyType)
                            .enumeration(KeyType::Table, [KeyType::Rsa4096, KeyType::Ed25519])
                            .not_null(),
                    )
                    .col(ColumnDef::new(Key::CredentialId).char_len(36).not_null())
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

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Key::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Claim::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(ProofState::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Proof::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(CredentialState::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Credential::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Did::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum Credential {
    Table,
    Id,
    CreatedDate,
    LastModified,
    IssuanceDate,
    DeletedAt,
    Transport,
    Credential,
    CredentialSchemaId,
    DidId,
}

#[derive(Iden)]
pub enum Transport {
    Table,
    #[iden = "PROCIVIS_TEMPORARY"]
    ProcivisTemporary,
    #[iden = "OPENID4VC"]
    OpenId4Vc,
}

#[derive(Iden)]
pub enum CredentialState {
    Table,
    CredentialId,
    CreatedDate,
    State,
}

#[derive(Iden)]
pub enum State {
    Table,
    #[iden = "CREATED"]
    Created,
    #[iden = "PENDING"]
    Pending,
    #[iden = "OFFERED"]
    Offered,
    #[iden = "ACCEPTED"]
    Accepted,
    #[iden = "REJECTED"]
    Rejected,
    #[iden = "REVOKED"]
    Revoked,
    #[iden = "ERROR"]
    Error,
}

#[derive(Iden)]
pub enum Did {
    Table,
    Id,
    Did,
    CreatedDate,
    LastModified,
    Name,
    Type,
    Method,
    OrganisationId,
}

#[derive(Iden)]
pub enum DidType {
    Table,
    #[iden = "REMOTE"]
    Remote,
    #[iden = "LOCAL"]
    Local,
}

#[derive(Iden)]
pub enum DidMethod {
    Table,
    #[iden = "KEY"]
    Key,
    #[iden = "WEB"]
    Web,
}

#[derive(Iden)]
pub enum Proof {
    Table,
    Id,
    CreatedDate,
    LastModified,
    IssuanceDate,
    DidId,
    ProofSchemaId,
}

#[derive(Iden)]
pub enum ProofState {
    Table,
    ProofId,
    CreatedDate,
    LastModified,
    State,
}

#[derive(Iden)]
pub enum ProofRequestState {
    Table,
    #[iden = "CREATED"]
    Created,
    #[iden = "PENDING"]
    Pending,
    #[iden = "OFFERED"]
    Offered,
    #[iden = "ACCEPTED"]
    Accepted,
    #[iden = "REJECTED"]
    Rejected,
    #[iden = "ERROR"]
    Error,
}

#[derive(Iden)]
pub enum Claim {
    Table,
    ClaimSchemaId,
    CredentialId,
    // ProofId,
    Value,
    CreatedDate,
    LastModified,
}

#[derive(Iden)]
pub enum Key {
    Table,
    DidId,
    CreatedDate,
    LastModified,
    PublicKey,
    PrivateKey,
    StorageType,
    KeyType,
    CredentialId,
}

#[derive(Iden)]
pub enum StorageType {
    Table,
    #[iden = "INTERN"]
    Intern,
    #[iden = "EXTERN"]
    Extern,
    #[iden = "INTERN_HSM"]
    InternHsm,
}

#[derive(Iden)]
pub enum KeyType {
    Table,
    #[iden = "RSA_4096"]
    Rsa4096,
    #[iden = "ED25519"]
    Ed25519,
}
