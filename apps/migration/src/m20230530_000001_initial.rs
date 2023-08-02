use std::fmt;

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Organisation::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Organisation::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Organisation::CreatedDate)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Organisation::LastModified)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CredentialSchema::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CredentialSchema::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchema::DeletedAt)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchema::CreatedDate)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchema::LastModified)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(ColumnDef::new(CredentialSchema::Name).string().not_null())
                    .col(
                        ColumnDef::new(CredentialSchema::Format)
                            .enumeration(
                                Format::Table,
                                [Format::Jwt, Format::SdJwt, Format::JsonLd, Format::Mdoc],
                            )
                            .not_null(),
                    )
                    .col(
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
                    .col(
                        ColumnDef::new(CredentialSchema::OrganisationId)
                            .char_len(36)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-CredentialSchema-OrganisationId")
                            .from_tbl(CredentialSchema::Table)
                            .from_col(CredentialSchema::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("index-CredentialSchema-Name")
                    .table(CredentialSchema::Table)
                    .col(CredentialSchema::OrganisationId)
                    .col(CredentialSchema::Name)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ClaimSchema::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ClaimSchema::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ClaimSchema::Key).string().not_null())
                    .col(
                        ColumnDef::new(ClaimSchema::Datatype)
                            .enumeration(
                                Datatype::Table,
                                [Datatype::String, Datatype::Date, Datatype::Number],
                            )
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClaimSchema::CreatedDate)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClaimSchema::LastModified)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ProofSchema::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProofSchema::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ProofSchema::DeletedAt)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchema::CreatedDate)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchema::LastModified)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(ColumnDef::new(ProofSchema::Name).string().not_null())
                    .col(
                        ColumnDef::new(ProofSchema::ExpireDuration)
                            .unsigned()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchema::OrganisationId)
                            .char_len(36)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-ProofSchema-OrganisationId")
                            .from_tbl(ProofSchema::Table)
                            .from_col(ProofSchema::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("index-ProofSchema-Name-Unique")
                    .unique()
                    .table(ProofSchema::Table)
                    .col(ProofSchema::OrganisationId)
                    .col(ProofSchema::Name)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CredentialSchemaClaimSchema::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CredentialSchemaClaimSchema::ClaimSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchemaClaimSchema::CredentialSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchemaClaimSchema::Required)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchemaClaimSchema::Order)
                            .unsigned()
                            .not_null()
                            .default(0),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-CredentialSchema_ClaimSchema")
                            .col(CredentialSchemaClaimSchema::ClaimSchemaId)
                            .col(CredentialSchemaClaimSchema::CredentialSchemaId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-CredentialSchema_ClaimSchema-ClaimId")
                            .from_tbl(CredentialSchemaClaimSchema::Table)
                            .from_col(CredentialSchemaClaimSchema::ClaimSchemaId)
                            .to_tbl(ClaimSchema::Table)
                            .to_col(ClaimSchema::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-CredentialSchema_ClaimSchema-ProofId")
                            .from_tbl(CredentialSchemaClaimSchema::Table)
                            .from_col(CredentialSchemaClaimSchema::CredentialSchemaId)
                            .to_tbl(CredentialSchema::Table)
                            .to_col(CredentialSchema::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ProofSchemaClaimSchema::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProofSchemaClaimSchema::ClaimSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchemaClaimSchema::ProofSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchemaClaimSchema::Required)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchemaClaimSchema::Order)
                            .unsigned()
                            .not_null()
                            .default(0),
                    )
                    .primary_key(
                        Index::create()
                            .if_not_exists()
                            .name("pk-ProofSchema_ClaimSchema")
                            .col(ProofSchemaClaimSchema::ClaimSchemaId)
                            .col(ProofSchemaClaimSchema::ProofSchemaId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ProofSchema_ClaimSchema-ClaimId")
                            .from_tbl(ProofSchemaClaimSchema::Table)
                            .from_col(ProofSchemaClaimSchema::ClaimSchemaId)
                            .to_tbl(ClaimSchema::Table)
                            .to_col(ClaimSchema::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ProofSchema_ClaimSchema-ProofId")
                            .from_tbl(ProofSchemaClaimSchema::Table)
                            .from_col(ProofSchemaClaimSchema::ProofSchemaId)
                            .to_tbl(ProofSchema::Table)
                            .to_col(ProofSchema::Id),
                    )
                    .to_owned(),
            )
            .await?;

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
                    .col(
                        ColumnDef::new(Did::CreatedDate)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Did::LastModified)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
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
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("index-Did-Did-Unique")
                    .unique()
                    .table(Did::Table)
                    .col(Did::Did)
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
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Credential::LastModified)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Credential::IssuanceDate)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Credential::DeletedAt)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .null(),
                    )
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
                    .col(ColumnDef::new(Credential::IssuerDidId).string().not_null())
                    .col(ColumnDef::new(Credential::ReceiverDidId).string())
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
                            .name("fk-Credential-IssuerDidId")
                            .from_tbl(Credential::Table)
                            .from_col(Credential::IssuerDidId)
                            .to_tbl(Did::Table)
                            .to_col(Did::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-Credential-ReceiverDidId")
                            .from_tbl(Credential::Table)
                            .from_col(Credential::ReceiverDidId)
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
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
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
                    .col(
                        ColumnDef::new(Proof::CreatedDate)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Proof::LastModified)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Proof::IssuanceDate)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(ColumnDef::new(Proof::VerifierDidId).string().not_null())
                    .col(ColumnDef::new(Proof::ReceiverDidId).string())
                    .col(ColumnDef::new(Proof::ProofSchemaId).char_len(36).not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-Proof-VerifierDidId")
                            .from_tbl(Proof::Table)
                            .from_col(Proof::VerifierDidId)
                            .to_tbl(Did::Table)
                            .to_col(Did::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-Proof-ReceiverDidId")
                            .from_tbl(Proof::Table)
                            .from_col(Proof::VerifierDidId)
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
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("index-ProofSchema-Name")
                    .table(ProofSchema::Table)
                    .col(ProofSchema::OrganisationId)
                    .col(ProofSchema::Name)
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
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofState::LastModified)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
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
                    .col(
                        ColumnDef::new(Claim::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Claim::ClaimSchemaId).char_len(36).not_null())
                    .col(ColumnDef::new(Claim::CredentialId).char_len(36).not_null())
                    .col(ColumnDef::new(Claim::Value).string().not_null())
                    .col(
                        ColumnDef::new(Claim::CreatedDate)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Claim::LastModified)
                            .custom::<CustomDateTime>(CustomDateTime(
                                manager.get_database_backend(),
                            ))
                            .not_null(),
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
                    .to_owned(),
            )
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

        manager
            .create_table(
                Table::create()
                    .table(ProofClaim::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(ProofClaim::ClaimId).char_len(36).not_null())
                    .col(ColumnDef::new(ProofClaim::ProofId).char_len(36).not_null())
                    .primary_key(
                        Index::create()
                            .name("pk-Proof_Claim")
                            .col(ProofClaim::ClaimId)
                            .col(ProofClaim::ProofId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-Proof_Claim-ClaimId")
                            .from_tbl(ProofClaim::Table)
                            .from_col(ProofClaim::ClaimId)
                            .to_tbl(Claim::Table)
                            .to_col(Claim::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-Proof_Claim-ProofId")
                            .from_tbl(ProofClaim::Table)
                            .from_col(ProofClaim::ProofId)
                            .to_tbl(Proof::Table)
                            .to_col(Proof::Id),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ProofClaim::Table).to_owned())
            .await?;
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

        manager
            .drop_table(
                Table::drop()
                    .table(ProofSchemaClaimSchema::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(ProofSchema::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(ClaimSchema::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(CredentialSchema::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Organisation::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum CredentialSchema {
    Table,
    Id,
    DeletedAt,
    CreatedDate,
    LastModified,
    Name,
    Format,
    RevocationMethod,
    OrganisationId,
}

#[derive(Iden)]
pub enum Format {
    Table,
    #[iden = "JWT"]
    Jwt,
    #[iden = "SD_JWT"]
    SdJwt,
    #[iden = "JSON_LD"]
    JsonLd,
    #[iden = "MDOC"]
    Mdoc,
}

#[derive(Iden)]
pub enum RevocationMethod {
    Table,
    #[iden = "NONE"]
    None,
    #[iden = "STATUSLIST2021"]
    StatusList2021,
    #[iden = "LVVC"]
    Lvvc,
}

#[derive(Iden)]
pub enum ClaimSchema {
    Table,
    Id,
    Datatype,
    Key,
    CreatedDate,
    LastModified,
}

#[derive(Iden)]
pub enum Datatype {
    Table,
    #[iden = "STRING"]
    String,
    #[iden = "DATE"]
    Date,
    #[iden = "NUMBER"]
    Number,
}

#[derive(Iden)]
pub enum ProofSchema {
    Table,
    Id,
    DeletedAt,
    CreatedDate,
    LastModified,
    Name,
    ExpireDuration,
    OrganisationId,
}

#[derive(Iden)]
pub enum ProofSchemaClaimSchema {
    Table,
    ClaimSchemaId,
    ProofSchemaId,
    Required,
    Order,
}

#[derive(Iden)]
pub enum CredentialSchemaClaimSchema {
    Table,
    ClaimSchemaId,
    CredentialSchemaId,
    Required,
    Order,
}

#[derive(Iden)]
pub enum Organisation {
    Table,
    Id,
    CreatedDate,
    LastModified,
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
    IssuerDidId,
    ReceiverDidId,
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
    VerifierDidId,
    ReceiverDidId,
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
    Id,
    ClaimSchemaId,
    CredentialId,
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

#[derive(Iden)]
pub enum ProofClaim {
    Table,
    ClaimId,
    ProofId,
}

struct CustomDateTime(sea_orm::DatabaseBackend);

impl Iden for CustomDateTime {
    fn unquoted(&self, s: &mut dyn fmt::Write) {
        let column_name = match self.0 {
            sea_orm::DatabaseBackend::MySql => "datetime(3)",
            sea_orm::DatabaseBackend::Postgres => "timestamp",
            sea_orm::DatabaseBackend::Sqlite => "datetime",
        };
        write!(s, "{column_name}").unwrap();
    }
}
