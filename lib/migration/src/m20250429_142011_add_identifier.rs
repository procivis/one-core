use sea_orm::{DatabaseBackend, EnumIter, Iterable};
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::{
    Credential, CredentialSchema, Did, Interaction, Key, Organisation, Proof, ProofSchema,
    RevocationList, State,
};
use crate::m20240118_070610_credential_add_role::CredentialRole;
use crate::m20240305_110029_suspend_credential_state::UpdatedStates;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Sqlite => {
                sqlite_migration(manager).await?;
            }
            _ => {
                sane_migration(manager).await?;
            }
        }
        Ok(())
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Identifier::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Identifier::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Identifier::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Identifier::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(ColumnDef::new(Identifier::Name).string().not_null())
                .col(
                    ColumnDef::new(Identifier::Type)
                        .enumeration(Identifier::Type, IdentifierType::iter())
                        .not_null(),
                )
                .col(ColumnDef::new(Identifier::IsRemote).boolean().not_null())
                .col(
                    ColumnDef::new(Identifier::Status)
                        .enumeration(Identifier::Status, IdentifierStatus::iter())
                        .not_null(),
                )
                .col(ColumnDef::new(Identifier::OrganisationId).char_len(36))
                .col(ColumnDef::new(Identifier::DidId).char_len(36))
                .col(ColumnDef::new(Identifier::KeyId).char_len(36))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_identifier_organisation")
                        .from(Identifier::Table, Identifier::OrganisationId)
                        .to(Organisation::Table, Organisation::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_identifier_did")
                        .from(Identifier::Table, Identifier::DidId)
                        .to(Did::Table, Did::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_identifier_key")
                        .from(Identifier::Table, Identifier::KeyId)
                        .to(Key::Table, Key::Id),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_table(
            Table::create()
                .table(CredentialNew::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(CredentialNew::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(CredentialNew::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::IssuanceDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::DeletedAt)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .col(ColumnDef::new(CredentialNew::Exchange).string().not_null())
                .col(
                    ColumnDef::new(CredentialNew::Credential)
                        .large_blob(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CredentialNew::CredentialSchemaId)
                        .char_len(36)
                        .not_null(),
                )
                .col(ColumnDef::new(CredentialNew::IssuerDidId).char_len(36))
                .col(ColumnDef::new(CredentialNew::HolderDidId).char_len(36))
                .col(ColumnDef::new(CredentialNew::InteractionId).char_len(36))
                .col(ColumnDef::new(CredentialNew::RevocationListId).char_len(36))
                .col(ColumnDef::new(CredentialNew::KeyId).char_len(36))
                .col(
                    ColumnDef::new(CredentialNew::Role)
                        .enumeration(
                            CredentialRole::Table,
                            [
                                CredentialRole::Holder,
                                CredentialRole::Issuer,
                                CredentialRole::Verifier,
                            ],
                        )
                        .not_null()
                        .default(CredentialRole::Issuer.to_string()),
                )
                .col(ColumnDef::new(CredentialNew::RedirectUri).string_len(1000))
                .col(
                    ColumnDef::new(CredentialNew::State)
                        .enumeration(State::Table, UpdatedStates::iter())
                        .not_null()
                        .default(State::Created.to_string()),
                )
                .col(
                    ColumnDef::new(CredentialNew::SuspendEndDate)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .col(ColumnDef::new(CredentialNew::HolderIdentifierId).char_len(36))
                .col(ColumnDef::new(CredentialNew::IssuerIdentifierId).char_len(36))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_credential_schema")
                        .from(CredentialNew::Table, CredentialNew::CredentialSchemaId)
                        .to(CredentialSchema::Table, CredentialSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_issuer_did")
                        .from(CredentialNew::Table, CredentialNew::IssuerDidId)
                        .to(Did::Table, Did::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_holder_did")
                        .from(CredentialNew::Table, CredentialNew::HolderDidId)
                        .to(Did::Table, Did::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_holder_identifier")
                        .from(CredentialNew::Table, CredentialNew::HolderIdentifierId)
                        .to(Identifier::Table, Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_issuer_identifier")
                        .from(CredentialNew::Table, CredentialNew::IssuerIdentifierId)
                        .to(Identifier::Table, Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_interaction")
                        .from(CredentialNew::Table, CredentialNew::InteractionId)
                        .to(Interaction::Table, Interaction::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_revocation_list")
                        .from(CredentialNew::Table, CredentialNew::RevocationListId)
                        .to(RevocationList::Table, RevocationList::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_key")
                        .from(CredentialNew::Table, CredentialNew::KeyId)
                        .to(Key::Table, Key::Id),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_table(
            Table::create()
                .table(ProofNew::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(ProofNew::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(ProofNew::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ProofNew::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ProofNew::IssuanceDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(ColumnDef::new(ProofNew::RedirectUri).string_len(1000))
                .col(ColumnDef::new(ProofNew::VerifierDidId).char_len(36))
                .col(ColumnDef::new(ProofNew::HolderDidId).char_len(36))
                .col(ColumnDef::new(ProofNew::ProofSchemaId).char_len(36))
                .col(ColumnDef::new(ProofNew::Transport).string().not_null())
                .col(ColumnDef::new(ProofNew::VerifierKeyId).char_len(36))
                .col(ColumnDef::new(ProofNew::InteractionId).char_len(36))
                .col(
                    ColumnDef::new(ProofNew::Exchange)
                        .string()
                        .not_null()
                        .default("OPENID4VC"),
                )
                .col(
                    ColumnDef::new(ProofNew::State)
                        .enumeration(State::Table, UpdatedStates::iter())
                        .not_null()
                        .default(State::Created.to_string()),
                )
                .col(
                    ColumnDef::new(ProofNew::RequestedDate).datetime_millisecond_precision(manager),
                )
                .col(
                    ColumnDef::new(ProofNew::CompletedDate).datetime_millisecond_precision(manager),
                )
                .col(
                    ColumnDef::new(ProofNew::Role)
                        .enumeration(CredentialRole::Table, [CredentialRole::Verifier])
                        .not_null()
                        .default(CredentialRole::Verifier.to_string()),
                )
                .col(ColumnDef::new(ProofNew::HolderIdentifierId).char_len(36))
                .col(ColumnDef::new(ProofNew::VerifierIdentifierId).char_len(36))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_verifier_did")
                        .from(ProofNew::Table, ProofNew::VerifierDidId)
                        .to(Did::Table, Did::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_holder_did")
                        .from(ProofNew::Table, ProofNew::HolderDidId)
                        .to(Did::Table, Did::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_proof_schema")
                        .from(ProofNew::Table, ProofNew::ProofSchemaId)
                        .to(ProofSchema::Table, ProofSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_interaction")
                        .from(ProofNew::Table, ProofNew::InteractionId)
                        .to(Interaction::Table, Interaction::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_holder_identifier")
                        .from(ProofNew::Table, ProofNew::HolderIdentifierId)
                        .to(Identifier::Table, Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_verifier_identifier")
                        .from(ProofNew::Table, ProofNew::VerifierIdentifierId)
                        .to(Identifier::Table, Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_verifier_key")
                        .from(ProofNew::Table, ProofNew::VerifierKeyId)
                        .to(Key::Table, Key::Id),
                )
                .to_owned(),
        )
        .await?;

    // Disable foreign keys for SQLite
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Copy credentials
    manager
        .get_connection()
        .execute_unprepared(
            r#"INSERT INTO credential_new
               SELECT *, NULL, NULL
               FROM credential;"#,
        )
        .await?;

    // Copy proofs
    manager
        .get_connection()
        .execute_unprepared(
            r#"INSERT INTO proof_new
               SELECT *, NULL, NULL
               FROM proof;"#,
        )
        .await?;

    manager
        .get_connection()
        .execute_unprepared(
            r#"DROP TABLE IF EXISTS `credential`;
               DROP TABLE IF EXISTS `proof`;
               ALTER TABLE `credential_new` RENAME TO `credential`;
               ALTER TABLE `proof_new` RENAME TO `proof`;"#,
        )
        .await?;

    // Enable foreign keys for SQLite
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

async fn sane_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Identifier::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(Identifier::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Identifier::CreatedDate)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Identifier::LastModified)
                        .datetime_millisecond_precision(manager)
                        .not_null(),
                )
                .col(ColumnDef::new(Identifier::Name).string().not_null())
                .col(
                    ColumnDef::new(Identifier::Type)
                        .enumeration(Identifier::Type, IdentifierType::iter())
                        .not_null(),
                )
                .col(ColumnDef::new(Identifier::IsRemote).boolean().not_null())
                .col(
                    ColumnDef::new(Identifier::Status)
                        .enumeration(Identifier::Status, IdentifierStatus::iter())
                        .not_null(),
                )
                .col(ColumnDef::new(Identifier::OrganisationId).char_len(36))
                .col(ColumnDef::new(Identifier::DidId).char_len(36))
                .col(ColumnDef::new(Identifier::KeyId).char_len(36))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_identifier_organisation")
                        .from(Identifier::Table, Identifier::OrganisationId)
                        .to(Organisation::Table, Organisation::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_identifier_did")
                        .from(Identifier::Table, Identifier::DidId)
                        .to(Did::Table, Did::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_identifier_key")
                        .from(Identifier::Table, Identifier::KeyId)
                        .to(Key::Table, Key::Id),
                )
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(Credential::Table)
                .add_column(ColumnDef::new(CredentialNew::HolderIdentifierId).char_len(36))
                .add_column(ColumnDef::new(CredentialNew::IssuerIdentifierId).char_len(36))
                .add_foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_holder_identifier")
                        .from(Credential::Table, CredentialNew::HolderIdentifierId)
                        .to(Identifier::Table, Identifier::Id)
                        .get_foreign_key(),
                )
                .add_foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_issuer_identifier")
                        .from(Credential::Table, CredentialNew::IssuerIdentifierId)
                        .to(Identifier::Table, Identifier::Id)
                        .get_foreign_key(),
                )
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(Proof::Table)
                .add_column(ColumnDef::new(ProofNew::HolderIdentifierId).char_len(36))
                .add_column(ColumnDef::new(ProofNew::VerifierIdentifierId).char_len(36))
                .add_foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_holder_identifier")
                        .from(Proof::Table, ProofNew::HolderIdentifierId)
                        .to(Identifier::Table, Identifier::Id)
                        .get_foreign_key(),
                )
                .add_foreign_key(
                    ForeignKey::create()
                        .name("fk_proof_verifier_identifier")
                        .from(Proof::Table, ProofNew::VerifierIdentifierId)
                        .to(Identifier::Table, Identifier::Id)
                        .get_foreign_key(),
                )
                .to_owned(),
        )
        .await?;

    Ok(())
}

#[derive(DeriveIden)]
pub enum Identifier {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Name,
    Type,
    IsRemote,
    Status,
    OrganisationId,
    DidId,
    KeyId,
}

#[derive(Iden, EnumIter)]
pub enum IdentifierType {
    #[iden = "KEY"]
    Key,
    #[iden = "DID"]
    Did,
    #[iden = "CERTIFICATE"]
    Certificate,
}

#[derive(Iden, EnumIter)]
pub enum IdentifierStatus {
    #[iden = "ACTIVE"]
    Active,
    #[iden = "DEACTIVATED"]
    Deactivated,
}

#[derive(DeriveIden, Clone)]
pub enum CredentialNew {
    Table,
    Id,
    CreatedDate,
    LastModified,
    IssuanceDate,
    DeletedAt,
    Exchange,
    Credential,
    CredentialSchemaId,
    IssuerDidId,
    HolderDidId,
    InteractionId,
    RevocationListId,
    KeyId,
    Role,
    RedirectUri,
    State,
    SuspendEndDate,
    HolderIdentifierId,
    IssuerIdentifierId,
}

#[derive(DeriveIden)]
pub enum ProofNew {
    Table,
    Id,
    CreatedDate,
    LastModified,
    IssuanceDate,
    RedirectUri,
    VerifierDidId,
    HolderDidId,
    ProofSchemaId,
    Transport,
    VerifierKeyId,
    InteractionId,
    Exchange,
    State,
    RequestedDate,
    CompletedDate,
    Role,
    HolderIdentifierId,
    VerifierIdentifierId,
}
