use std::fmt;

use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;

#[derive(DeriveMigrationName)]
pub struct Migration;

pub const UNIQUE_DID_DID_INDEX: &str = "index-Did-Did-Unique";
pub const CREDENTIAL_SCHEMA_NAME_IN_ORGANISATION_INDEX: &str = "index-CredentialSchema-Name";
pub const PROOF_SCHEMA_NAME_IN_ORGANISATION_INDEX: &str = "index-ProofSchema-Name";
pub const UNIQUE_PROOF_SCHEMA_ORGANISATION_ID_NAME_INDEX: &str = "index-ProofSchema-Name-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let datetime = CustomDateTime(manager.get_database_backend());

        manager
            .create_table(
                Table::create()
                    .table(Interaction::Table)
                    .col(
                        ColumnDef::new(Interaction::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Interaction::CreatedDate)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Interaction::LastModified)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Interaction::Host).string())
                    .col(ColumnDef::new(Interaction::Data).custom_blob(manager))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Organisation::Table)
                    .col(
                        ColumnDef::new(Organisation::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Organisation::CreatedDate)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Organisation::LastModified)
                            .custom(datetime)
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CredentialSchema::Table)
                    .col(
                        ColumnDef::new(CredentialSchema::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchema::DeletedAt)
                            .custom(datetime)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchema::CreatedDate)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchema::LastModified)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(ColumnDef::new(CredentialSchema::Name).string().not_null())
                    .col(ColumnDef::new(CredentialSchema::Format).string().not_null())
                    .col(
                        ColumnDef::new(CredentialSchema::RevocationMethod)
                            .string()
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
                    .name(CREDENTIAL_SCHEMA_NAME_IN_ORGANISATION_INDEX)
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
                    .col(
                        ColumnDef::new(ClaimSchema::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ClaimSchema::Key).string().not_null())
                    .col(ColumnDef::new(ClaimSchema::Datatype).string().not_null())
                    .col(
                        ColumnDef::new(ClaimSchema::CreatedDate)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClaimSchema::LastModified)
                            .custom(datetime)
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ProofSchema::Table)
                    .col(
                        ColumnDef::new(ProofSchema::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ProofSchema::DeletedAt)
                            .custom(datetime)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchema::CreatedDate)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchema::LastModified)
                            .custom(datetime)
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
                    .name(UNIQUE_PROOF_SCHEMA_ORGANISATION_ID_NAME_INDEX)
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
                    .col(
                        ColumnDef::new(CredentialSchemaClaimSchema::ClaimSchemaId)
                            .char_len(36)
                            .not_null()
                            // this table is in a one-to-one relation with ClaimSchema, so setting ClaimSchemaId as primary/unique key
                            .primary_key(),
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
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-CredentialSchemaClaimSchema-ClaimSchemaId")
                            .from_tbl(CredentialSchemaClaimSchema::Table)
                            .from_col(CredentialSchemaClaimSchema::ClaimSchemaId)
                            .to_tbl(ClaimSchema::Table)
                            .to_col(ClaimSchema::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-CredentialSchemaClaimSchema-CredentialSchemaId")
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
                            .name("pk-ProofSchemaClaimSchema")
                            .col(ProofSchemaClaimSchema::ClaimSchemaId)
                            .col(ProofSchemaClaimSchema::ProofSchemaId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ProofSchemaClaimSchema-ClaimSchemaId")
                            .from_tbl(ProofSchemaClaimSchema::Table)
                            .from_col(ProofSchemaClaimSchema::ClaimSchemaId)
                            .to_tbl(ClaimSchema::Table)
                            .to_col(ClaimSchema::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ProofSchemaClaimSchema-ProofSchemaId")
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
                    .col(
                        ColumnDef::new(Did::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Did::Did).string_len(4000).not_null())
                    .col(ColumnDef::new(Did::CreatedDate).custom(datetime).not_null())
                    .col(
                        ColumnDef::new(Did::LastModified)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Did::Name).string().not_null())
                    .col(
                        ColumnDef::new(Did::Type)
                            .enumeration(DidType::Table, [DidType::Remote, DidType::Local])
                            .not_null(),
                    )
                    .col(ColumnDef::new(Did::Method).string().not_null())
                    .col(ColumnDef::new(Did::OrganisationId).char_len(36).not_null())
                    .col(ColumnDef::new(Did::Deactivated).boolean().not_null())
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
                    .name(UNIQUE_DID_DID_INDEX)
                    .unique()
                    .table(Did::Table)
                    .col(Did::Did)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(RevocationList::Table)
                    .col(
                        ColumnDef::new(RevocationList::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(RevocationList::CreatedDate)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RevocationList::LastModified)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RevocationList::Credentials)
                            .custom_blob(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RevocationList::IssuerDidId)
                            .char_len(36)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-RevocationList-IssuerDidId")
                            .from_tbl(RevocationList::Table)
                            .from_col(RevocationList::IssuerDidId)
                            .to_tbl(Did::Table)
                            .to_col(Did::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Key::Table)
                    .col(
                        ColumnDef::new(Key::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Key::CreatedDate).custom(datetime).not_null())
                    .col(
                        ColumnDef::new(Key::LastModified)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Key::Name).string().not_null())
                    .col(
                        ColumnDef::new(Key::PublicKey)
                            .custom_blob(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Key::KeyReference)
                            .custom_blob(manager)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Key::StorageType).string().not_null())
                    .col(ColumnDef::new(Key::KeyType).string().not_null())
                    .col(ColumnDef::new(Key::OrganisationId).char_len(36).not_null())
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-Key-OrganisationId")
                            .from_tbl(Key::Table)
                            .from_col(Key::OrganisationId)
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
                    .col(
                        ColumnDef::new(Credential::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Credential::CreatedDate)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Credential::LastModified)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Credential::IssuanceDate)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Credential::DeletedAt)
                            .custom(datetime)
                            .null(),
                    )
                    .col(ColumnDef::new(Credential::Transport).string().not_null())
                    .col(ColumnDef::new(Credential::RedirectUri).string())
                    .col(
                        ColumnDef::new(Credential::Credential)
                            .custom_blob(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Credential::CredentialSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Credential::IssuerDidId).char_len(36))
                    .col(ColumnDef::new(Credential::HolderDidId).char_len(36))
                    .col(ColumnDef::new(Credential::InteractionId).char_len(36))
                    .col(ColumnDef::new(Credential::RevocationListId).char_len(36))
                    .col(ColumnDef::new(Credential::KeyId).char_len(36))
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
                            .name("fk-Credential-HolderDidId")
                            .from_tbl(Credential::Table)
                            .from_col(Credential::HolderDidId)
                            .to_tbl(Did::Table)
                            .to_col(Did::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-Credential-InteractionId")
                            .from_tbl(Credential::Table)
                            .from_col(Credential::InteractionId)
                            .to_tbl(Interaction::Table)
                            .to_col(Interaction::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-Credential-RevocationListId")
                            .from_tbl(Credential::Table)
                            .from_col(Credential::RevocationListId)
                            .to_tbl(RevocationList::Table)
                            .to_col(RevocationList::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-Credential-KeyId")
                            .from_tbl(Credential::Table)
                            .from_col(Credential::KeyId)
                            .to_tbl(Key::Table)
                            .to_col(Key::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CredentialState::Table)
                    .col(
                        ColumnDef::new(CredentialState::CredentialId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialState::CreatedDate)
                            .custom(datetime)
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
                    .col(
                        ColumnDef::new(Proof::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Proof::CreatedDate)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Proof::LastModified)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Proof::IssuanceDate)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Proof::RedirectUri).string())
                    .col(ColumnDef::new(Proof::VerifierDidId).char_len(36))
                    .col(ColumnDef::new(Proof::HolderDidId).char_len(36))
                    .col(ColumnDef::new(Proof::ProofSchemaId).char_len(36))
                    .col(ColumnDef::new(Proof::Transport).string().not_null())
                    .col(ColumnDef::new(Proof::InteractionId).char_len(36))
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
                            .name("fk-Proof-HolderDidId")
                            .from_tbl(Proof::Table)
                            .from_col(Proof::HolderDidId)
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
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-Proof-InteractionId")
                            .from_tbl(Proof::Table)
                            .from_col(Proof::InteractionId)
                            .to_tbl(Interaction::Table)
                            .to_col(Interaction::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(PROOF_SCHEMA_NAME_IN_ORGANISATION_INDEX)
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
                    .col(ColumnDef::new(ProofState::ProofId).char_len(36).not_null())
                    .col(
                        ColumnDef::new(ProofState::CreatedDate)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofState::LastModified)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofState::State)
                            .enumeration(
                                ProofRequestStateEnum,
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
                    .col(
                        ColumnDef::new(Claim::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Claim::ClaimSchemaId).char_len(36).not_null())
                    .col(ColumnDef::new(Claim::CredentialId).char_len(36).not_null())
                    .col(ColumnDef::new(Claim::Value).custom_blob(manager).not_null())
                    .col(
                        ColumnDef::new(Claim::CreatedDate)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Claim::LastModified)
                            .custom(datetime)
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
                    .table(KeyDid::Table)
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
                            .col(KeyDid::Role)
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
                            .to_col(Key::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ProofClaim::Table)
                    .col(ColumnDef::new(ProofClaim::ClaimId).char_len(36).not_null())
                    .col(ColumnDef::new(ProofClaim::ProofId).char_len(36).not_null())
                    .primary_key(
                        Index::create()
                            .name("pk-ProofClaim")
                            .col(ProofClaim::ClaimId)
                            .col(ProofClaim::ProofId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ProofClaim-ClaimId")
                            .from_tbl(ProofClaim::Table)
                            .from_col(ProofClaim::ClaimId)
                            .to_tbl(Claim::Table)
                            .to_col(Claim::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ProofClaim-ProofId")
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
            .drop_table(Table::drop().table(KeyDid::Table).to_owned())
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
            .drop_table(Table::drop().table(Key::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(RevocationList::Table).to_owned())
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
            .drop_table(
                Table::drop()
                    .table(CredentialSchemaClaimSchema::Table)
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

        manager
            .drop_table(Table::drop().table(Interaction::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum Interaction {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Host,
    Data,
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
pub enum ClaimSchema {
    Table,
    Id,
    Datatype,
    Key,
    CreatedDate,
    LastModified,
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
#[allow(clippy::enum_variant_names)]
pub enum Credential {
    Table,
    Id,
    CreatedDate,
    LastModified,
    IssuanceDate,
    DeletedAt,
    Transport,
    RedirectUri,
    Credential,
    CredentialSchemaId,
    IssuerDidId,
    HolderDidId,
    InteractionId,
    RevocationListId,
    KeyId,
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
#[allow(clippy::enum_variant_names)]
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
    Deactivated,
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
#[allow(clippy::enum_variant_names)]
pub enum Proof {
    Table,
    Id,
    CreatedDate,
    LastModified,
    IssuanceDate,
    Transport,
    RedirectUri,
    VerifierDidId,
    HolderDidId,
    ProofSchemaId,
    InteractionId,
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
pub struct ProofRequestStateEnum;

#[derive(Iden)]
pub enum ProofRequestState {
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
#[allow(clippy::enum_variant_names)]
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
#[allow(clippy::enum_variant_names)]
pub enum Key {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Name,
    PublicKey,
    KeyReference,
    StorageType,
    KeyType,
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

#[derive(Iden)]
pub enum RevocationList {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Credentials,
    IssuerDidId,
}

#[derive(Iden)]
pub enum ProofClaim {
    Table,
    ClaimId,
    ProofId,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct CustomDateTime(pub sea_orm::DatabaseBackend);

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
