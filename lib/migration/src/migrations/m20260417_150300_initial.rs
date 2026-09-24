#![allow(clippy::enum_variant_names)]

use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{
    big_integer, boolean, json_null, string, string_len, string_len_null, string_null, text,
    text_null, unsigned, unsigned_null, var_binary_null,
};

use crate::datatype::{
    large_blob, large_blob_null, timestamp, timestamp_null, timestamp_seconds, uuid_char,
    uuid_char_null,
};
use crate::foreign_key::disable_foreign_key_checks;
use crate::index_helper::table_with_indexes;
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

// Org table
const FK_ORGANISATION_PARENT_ORGANISATION: &str = "fk-Organisation-ParentOrganisation";
const FK_ORGANISATION_IDENTIFIER: &str = "fk-OrganisationWalletUnitIssuer-IssuerId";

const INDEX_ORGANISATION_PARENT_ORGANISATION: &str = "index-Organisation-ParentOrganisation";

const INDEX_UNIQUE_ORGANISATION_WALLET_PROVIDER: &str = "index-Organisation-WalletProvider-Unique";

// History Table
const FK_HISTORY_ORGANISATION: &str = "fk-History-OrganisationId-new";
const FK_HISTORY_BLOB: &str = "fk-History-MetadataBlobId";

const INDEX_HISTORY_CREATED_DATE: &str = "index-History-CreatedDate";
const INDEX_HISTORY_ENTITY: &str = "index-History-EntityId";
const INDEX_HISTORY_METADATA: &str = "index-History-Metadata";
const INDEX_HISTORY_ORG_CREATED_DATE: &str = "index-History-Org-CreatedDate";

// Remote Entity Cache Table
const INDEX_UNIQUE_REMOTE_ENTITY_CACHE_KEY: &str = "index-RemoteEntityCache-Key-Unique";
const INDEX_REMOTE_ENTITY_CACHE_TYPE_EXPIRATION_DATE: &str =
    "index-RemoteEntityCache-Type-ExpirationDate";

// Notification Table
const FK_NOTIFICATION_ORGANISATION: &str = "fk-Notification-OrganisationId";

const INDEX_NOTIFICATION_CREATED_DATE: &str = "index-Notification-CreatedDate";
const INDEX_NOTIFICATION_NEXT_TRY_DATE: &str = "index-Notification-Type_NextTryDate";

// Key Table
const FK_KEY_ORGANISATION: &str = "fk-Key-OrganisationId";

const INDEX_UNIQUE_KEY_NAME_ORGANISATION_DELETED_AT: &str =
    "index_Key_Name-OrganisationId-DeletedAt_Unique";
const INDEX_KEY_CREATED_DATE: &str = "index-Key-CreatedDate";

// Did Table
const FK_DID_ORGANISATION: &str = "fk-Did-OrganisationId";

const INDEX_UNIQUE_DID_NAME_ORGANISATION_DELETED_AT: &str =
    "index_Did_Name-OrganisationId-DeletedAt_Unique";
pub(crate) const INDEX_UNIQUE_DID_DID_ORGANISATION: &str = "index-Did-Did-OrganisationId-Unique";
const INDEX_DID_CREATED_DATE: &str = "index-Did-CreatedDate";
const INDEX_DID_DID: &str = "index-Did-Did";

// Key Did Table
const FK_KEY_DID_KEY: &str = "fk-KeyDid-KeyId";
const FK_KEY_DID_DID: &str = "fk-KeyDid-DidId";

// Identifier Table
const FK_IDENTIFIER_ORGANISATION: &str = "fk_identifier_organisation";
const FK_IDENTIFIER_DID: &str = "fk_identifier_did";
const FK_IDENTIFIER_KEY: &str = "fk_identifier_key";

const INDEX_UNIQUE_IDENTIFIER_NAME_ORGANISATION_DELETED_AT: &str =
    "index_Identifier_Name-OrganisationId-DeletedAt_Unique";

// Certificate Table
const FK_CERTIFICATE_ORGANISATION: &str = "fk_certificate_organisation_id";
const FK_CERTIFICATE_IDENTIFIER: &str = "fk_certificate_identifier";
const FK_CERTIFICATE_KEY: &str = "fk_certificate_key";

const INDEX_UNIQUE_CERTIFICATE_FINGERPRINT_ORGANISATION_DELETED_AT: &str =
    "index-Certificate-Fingerprint-OrganisationId-Unique";
const INDEX_UNIQUE_CERTIFICATE_NAME_EXPIRY_DATE_IDENTIFIER: &str =
    "index-Certificate-Name-ExpiryDate-IdentifierId-Unique";

// Identifier Trust Information
const FK_IDENTIFIER_TRUST_INFORMATION_BLOB: &str = "fk-IdentifierTrustInformation-BlobStorage";
const FK_IDENTIFIER_TRUST_INFORMATION_IDENTIFIER: &str = "fk-IdentifierTrustInformation-Identifier";

const INDEX_UNIQUE_IDENTIFIER_TRUST_INFORMATION_IDENTIFIER_BLOB: &str =
    "index-IdentifierTrustInformation-IdentifierId-BlobId-Unique";

// Credential Schema Table
const FK_CREDENTIAL_SCHEMA_ORGANISATION: &str = "fk-CredentialSchema-OrganisationId";

const INDEX_UNIQUE_CREDENTIAL_SCHEMA_NAME_ORGANISATION_DELETED_AT: &str =
    "index_CredentialSchema_Name-OrganisationId-DeletedAt_Unique";
const INDEX_UNIQUE_CREDENTIAL_SCHEMA_SCHEMA_ID_ORGANISATION_DELETED_AT: &str =
    "index-Organisation-SchemaId-DeletedAt_Unique";
const INDEX_CREDENTIAL_SCHEMA_CREATED_DATE: &str = "index-CredentialSchema-CreatedDate";

// Claim Schema Table
const FK_CLAIM_SCHEMA_CREDENTIAL_SCHEMA: &str = "fk_claim_schema_credential_schema_id";

// Proof Schema Table
const FK_PROOF_SCHEMA_ORGANISATION: &str = "fk-ProofSchema-OrganisationId";

const INDEX_UNIQUE_PROOF_SCHEMA_NAME_ORGANISATION_DELETED_AT: &str =
    "index_ProofSchema_Name-OrganisationId-DeletedAt_Unique";

const INDEX_PROOF_SCHEMA_CREATED_DATE: &str = "index-ProofSchema-CreatedDate";

// Proof Input Schema
const FK_PROOF_INPUT_SCHEMA_CREDENTIAL_SCHEMA: &str = "fk-ProofInputSchema-CredentialSchema";
const FK_PROOF_INPUT_SCHEMA_PROOF_SCHEMA: &str = "fk-ProofInputSchema-ProofSchema";

// Proof Input Claim Schema
const FK_PROOF_INPUT_CLAIM_SCHEMA_CLAIM_SCHEMA: &str = "fk-ProofInputClaimSchema-ClaimSchemaId";
const FK_PROOF_INPUT_CLAIM_SCHEMA_PROOF_INPUT_SCHEMA: &str =
    "fk-ProofInputClaimSchema-ProofSchemaId";

// Interaction Table
const FK_INTERACTION_ORGANISATION: &str = "fk-interaction-OrganisationId";

const INDEX_UNIQUE_INTERACTION_NONCE_ID: &str = "index-Interaction-NonceId-Unique";

const INDEX_INTERACTION_EXPIRES_AT: &str = "index-Interaction-ExpiresAt";

// Credential Table
pub(crate) const FK_CREDENTIAL_CREDENTIAL_SCHEMA: &str = "fk-Credential-CredentialSchemaId";
pub(crate) const FK_CREDENTIAL_INTERACTION: &str = "fk-Credential-InteractionId";
pub(crate) const FK_CREDENTIAL_HOLDER_IDENTIFIER: &str = "fk_credential_holder_identifier";
pub(crate) const FK_CREDENTIAL_KEY: &str = "fk-Credential-KeyId";
pub(crate) const FK_CREDENTIAL_ISSUER_IDENTIFIER: &str = "fk_credential_issuer_identifier";
pub(crate) const FK_CREDENTIAL_ISSUER_CERTIFICATE: &str = "fk-credential-issuer_certificate";
pub(crate) const FK_CREDENTIAL_CREDENTIAL_BLOB: &str = "fk_credential_credential_blob_id";
pub(crate) const FK_CREDENTIAL_WALLET_UNIT_ATTESTATION_BLOB: &str =
    "fk_credential_wallet_unit_attestation_blob_id";
pub(crate) const FK_CREDENTIAL_WALLET_INSTANCE_ATTESTATION_BLOB: &str =
    "fk_credential_wallet_instance_attestation_blob_id";

pub(crate) const INDEX_CREDENTIAL_LIST: &str = "idx_credential_list";
pub(crate) const INDEX_CREDENTIAL_CREATED_DATE: &str = "index-Credential-CreatedDate";
pub(crate) const INDEX_CREDENTIAL_DELETED_AT: &str = "index-Credential-DeletedAt";
pub(crate) const INDEX_CREDENTIAL_ROLE: &str = "index-Credential-Role";
pub(crate) const INDEX_CREDENTIAL_STATE: &str = "index-Credential-State";
pub(crate) const INDEX_CREDENTIAL_SUSPEND_END_DATE: &str = "index-Credential-SuspendEndDate";

// Claim Table
const FK_CLAIM_CLAIM_SCHEMA: &str = "fk-Claim-ClaimSchemaId";
const FK_CLAIM_CREDENTIAL: &str = "fk-Claim-CredentialId";

// Revocation List Table
const FK_REVOCATION_LIST_CERTIFICATE: &str = "fk_revocation_list_issuer_certificate_id";
const FK_REVOCATION_LIST_IDENTIFIER: &str = "fk_revocation_list_issuer_identifier_id";

const INDEX_UNIQUE_REVOCATION_LIST_IDENTIFIER_CERTIFICATE_PURPOSE_TYPE: &str =
    "index-IssuerIdentifierId-IssuerCertificateId-Purpose-Type-Unique";

// Revocation List Entry Table
const FK_REVOCATION_LIST_ENTRY_REVOCATION_LIST: &str = "fk-RevocationListEntry-RevocationListId";
const FK_REVOCATION_LIST_ENTRY_CREDENTIAL: &str = "fk-RevocationListEntry-CredentialId";

const INDEX_UNIQUE_REVOCATION_LIST_ENTRY_REVOCATION_LIST_INDEX: &str =
    "index-RevocationList-Index-Unique";
const INDEX_UNIQUE_REVOCATION_LIST_ENTRY_REVOCATION_LIST_SERIAL: &str =
    "index-RevocationList-Serial-Unique";

// Validity Credential Table
const FK_VALIDITY_CREDENTIAL_CREDENTIAL: &str = "fk-Lvvc-CredentialId";

// Proof Table
const FK_PROOF_INTERACTION: &str = "fk-Proof-InteractionId";
const FK_PROOF_PROOF_SCHEMA: &str = "fk-Proof-ProofSchemaId";
const FK_PROOF_VERIFIER_IDENTIFIER: &str = "fk_proof_verifier_identifier";
const FK_PROOF_VERIFIER_CERTIFICATE: &str = "fk-proof-verifier_certificate";
const FK_PROOF_VERIFIER_KEY: &str = "fk-Proof-VerifierKeyId";
const FK_PROOF_PROOF_BLOB: &str = "fk_proof_proof_blob_id";

const INDEX_PROOF_CREATED_DATE: &str = "index-Proof-CreatedDate";

// Proof Claim Table
const FK_PROOF_CLAIM_CLAIM: &str = "fk-ProofClaim-ClaimId";
const FK_PROOF_CLAIM_PROOF: &str = "fk-ProofClaim-ProofId";

// Wallet Instance Table
const FK_WALLET_INSTANCE_ORGANISATION: &str = "fk-WalletUnit-OrganisationId";
const INDEX_UNIQUE_WALLET_INSTANCE_AUTHENTICATION_KEY_ORGANISATION: &str =
    "index-WalletUnit-Organisation-AuthenticationKey-Unique";

// Wallet Instance Attested Key Table
const FK_WALLET_INSTANCE_ATTESTED_KEY_REVOCATION_LIST_ENTRY: &str =
    "fk-WalletUnitAttestedKey-RevocationListEntry";
const FK_WALLET_INSTANCE_ATTESTED_KEY_WALLET_INSTANCE: &str = "fk-WalletUnitAttestedKey-WalletUnit";

// Holder Wallet Instance Table
const FK_HOLDER_WALLET_INSTANCE_ORGANISATION: &str = "fk-HolderWalletUnit-Organisation";
const FK_HOLDER_WALLET_INSTANCE_KEY: &str = "fk-HolderWalletUnitAuthKey-Key";

const INDEX_UNIQUE_HOLDER_WALLET_INSTANCE_ORGANISATION: &str =
    "index-HolderWalletUnit-OrganisationId-Unique";

// Wallet Instance Attestation Table
const FK_WALLET_INSTANCE_ATTESTATION_HOLDER_WALLET_INSTANCE: &str =
    "fk-WalletUnitAttestation-HolderWalletUnit";
const FK_WALLET_INSTANCE_ATTESTATION_KEY: &str = "fk-WalletUnitAttestation-KeyId";

const INDEX_UNIQUE_WALLET_INSTANCE_ATTESTATION_KEY: &str =
    "index-WalletUnitAttestation-AttestedKey-Unique";

// Verifier Instance Table
const FK_VERIFIER_INSTANCE_ORGANISATION: &str = "fk-VerifierInstance-Organisation";

const INDEX_UNIQUE_VERIFIER_INSTANCE_ORGANISATION: &str =
    "index-VerifierInstance-OrganisationId-Unique";

// Trust List Publication Table
const FK_TRUST_LIST_PUBLICATION_ORGANISATION: &str = "fk-TrustListPublication-OrganisationId";
const FK_TRUST_LIST_PUBLICATION_IDENTIFIER: &str = "fk-TrustListPublication-IdentifierId";
const FK_TRUST_LIST_PUBLICATION_CERTIFICATE: &str = "fk-TrustListPublication-CertificateId";
const FK_TRUST_LIST_PUBLICATION_KEY: &str = "fk-TrustListPublication-KeyId";

const INDEX_UNIQUE_TRUST_LIST_PUBLICATION_NAME_ORGANISATION_DEACTIVATED_AT: &str =
    "index-TrustPublication-Name-Org-DeactivatedAt-Unique";

// Trust Entry Table
const FK_TRUST_ENTRY_PUBLICATION: &str = "fk-TrustEntry-TrustListPublicationId";
const FK_TRUST_ENTRY_IDENTIFIER: &str = "fk-TrustEntry-IdentifierId";

const INDEX_UNIQUE_TRUST_ENTRY_IDENTIFIER_PUBLICATION: &str =
    "index-TrustEntry-IdentifierId-Publication-Unique";

// Trust Collection Table
const FK_TRUST_COLLECTION_ORGANISATION: &str = "fk-TrustCollection-OrganisationId";

const INDEX_UNIQUE_TRUST_COLLECTION_NAME_ORGANISATION_DEACTIVATED_AT: &str =
    "index-TrustCol-Name-Org-DeactivatedAt-Unique";

// Trust List Subscription Table
const FK_TRUST_LIST_SUBSCRIPTION_COLLECTION: &str = "fk-TrustListSubscription-TrustCollectionId";

const INDEX_UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_COLLECTION_DEACTIVATED_AT: &str =
    "index-TrustListSubscription-Name-Col-DeactivatedAt-Unique";
const INDEX_UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_COLLECTION_DEACTIVATED_AT: &str =
    "index-TrustListSubscription-Reference-Col-DeactivatedAt-Unique";

// Trust Anchor Table
const INDEX_UNIQUE_TRUST_ANCHOR_NAME: &str = "UK-TrustAnchor-Name";

// Trust Entity Table
const FK_TRUST_ENTITY_TRUST_ANCHOR: &str = "FK-TrustEntity-TrustAnchorId";
const FK_TRUST_ENTITY_ORGANISATION: &str = "FK-TrustEntity-OrganisationId";

const INDEX_UNIQUE_TRUST_ENTITY_NAME_ORGANISATION_DEACTIVATED_AT: &str =
    "idx-TrustEntity-Name-OrganisationId-DeactivatedAt-Unique";
const INDEX_UNIQUE_TRUST_ENTITY_ENTITY_KEY_ANCHOR_DEACTIVATED_AT: &str =
    "idx-TrustEntity-EntityKey-AnchorId-DeactivatedAt-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        disable_foreign_key_checks(manager).await?;

        organisation_table(manager).await?;
        blob_storage_table(manager).await?;
        history_table(manager).await?;
        remote_entity_cache_table(manager).await?;
        notification_table(manager).await?;

        key_table(manager).await?;
        did_table(manager).await?;
        key_did_table(manager).await?;
        identifier_table(manager).await?;
        certificate_table(manager).await?;
        identifier_trust_information_table(manager).await?;

        credential_schema_table(manager).await?;
        claim_schema_table(manager).await?;

        proof_schema_table(manager).await?;
        proof_input_schema_table(manager).await?;
        proof_input_claim_schema_table(manager).await?;

        interaction_table(manager).await?;

        credential_table(manager).await?;
        claim_table(manager).await?;

        proof_table(manager).await?;
        proof_claim_table(manager).await?;

        revocation_list_table(manager).await?;
        revocation_list_entry_table(manager).await?;
        validity_credential_table(manager).await?;

        // provider side
        wallet_instance_table(manager).await?;
        wallet_instance_attested_key_table(manager).await?;

        // holder side
        holder_wallet_instance_table(manager).await?;
        wallet_instance_attestation_table(manager).await?;
        verifier_instance_table(manager).await?;

        trust_list_publication_table(manager).await?;
        trust_entry_table(manager).await?;

        trust_collection_table(manager).await?;
        trust_list_subscription_table(manager).await?;

        trust_anchor_table(manager).await?;
        trust_entity_table(manager).await?;

        foreign_key_postprocessing(manager).await?;

        if manager.supported_db_type() == SupportedDbType::Postgres {
            // Postgres compatibility shim for hex() function.
            manager
                .get_connection()
                .execute_unprepared(
                    r#"
                    create function hex(bytea) returns text language sql immutable strict as $$
                      select encode($1, 'hex')
                    $$;
                    "#,
                )
                .await?;
        }
        Ok(())
    }
}

async fn foreign_key_postprocessing(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    match manager.supported_db_type() {
        SupportedDbType::MySql => {
            manager
                .get_connection()
                .execute_unprepared("SET FOREIGN_KEY_CHECKS=1;")
                .await?;
        }
        SupportedDbType::Postgres => {
            // Add the circular foreign key constraint that was skipped earlier.
            manager
                .alter_table(
                    Table::alter()
                        .table(Organisation::Table)
                        .add_foreign_key(
                            ForeignKeyCreateStatement::new()
                                .name(FK_ORGANISATION_IDENTIFIER)
                                .from_tbl(Organisation::Table)
                                .from_col(Organisation::WalletProviderIssuer)
                                .to_tbl(Identifier::Table)
                                .to_col(Identifier::Id)
                                .get_foreign_key(),
                        )
                        .to_owned(),
                )
                .await?;
        }
        SupportedDbType::Sqlite => {
            manager
                .get_connection()
                .execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
                .await?;
        }
    }
    Ok(())
}

async fn organisation_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let mut table = Table::create()
        .if_not_exists()
        .table(Organisation::Table)
        .col(uuid_char(Organisation::Id).primary_key())
        .col(timestamp(Organisation::CreatedDate, manager))
        .col(timestamp(Organisation::LastModified, manager))
        .col(timestamp_null(Organisation::DeactivatedAt, manager))
        .col(string_null(Organisation::WalletProvider))
        .col(uuid_char_null(Organisation::ParentOrganisation))
        .col(uuid_char_null(Organisation::WalletProviderIssuer))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_ORGANISATION_PARENT_ORGANISATION)
                .from_tbl(Organisation::Table)
                .from_col(Organisation::ParentOrganisation)
                .to_tbl(Organisation::Table)
                .to_col(Organisation::Id)
                .on_delete(ForeignKeyAction::SetNull),
        )
        .to_owned();

    if manager.supported_db_type() != SupportedDbType::Postgres {
        // we add this later for Postgres, as it doesn't support to globally disable foreign key constraints
        table.foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_ORGANISATION_IDENTIFIER)
                .from_tbl(Organisation::Table)
                .from_col(Organisation::WalletProviderIssuer)
                .to_tbl(Identifier::Table)
                .to_col(Identifier::Id),
        );
    }

    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_ORGANISATION_PARENT_ORGANISATION)
            .table(Organisation::Table)
            .col(Organisation::ParentOrganisation)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_ORGANISATION_WALLET_PROVIDER)
            .unique()
            .table(Organisation::Table)
            .col(Organisation::WalletProvider)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn blob_storage_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(BlobStorage::Table)
                .col(uuid_char(BlobStorage::Id).primary_key())
                .col(timestamp(BlobStorage::CreatedDate, manager))
                .col(timestamp(BlobStorage::LastModified, manager))
                .col(string(BlobStorage::Type))
                .col(large_blob(BlobStorage::Value, manager))
                .to_owned(),
        )
        .await
}

async fn history_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(History::Table)
        .col(uuid_char(History::Id).primary_key())
        .col(timestamp(History::CreatedDate, manager))
        .col(string(History::Name))
        .col(string(History::Action))
        .col(string(History::Source))
        .col(string(History::EntityType))
        .col(string_null(History::User))
        .col(string_null(History::Target))
        .col(text_null(History::Metadata))
        .col(uuid_char_null(History::OrganisationId))
        .col(uuid_char_null(History::EntityId))
        .col(uuid_char_null(History::MetadataBlobId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_HISTORY_ORGANISATION)
                .from_tbl(History::Table)
                .from_col(History::OrganisationId)
                .to_tbl(Organisation::Table)
                .to_col(Organisation::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_HISTORY_BLOB)
                .from_tbl(History::Table)
                .from_col(History::MetadataBlobId)
                .to_tbl(BlobStorage::Table)
                .to_col(BlobStorage::Id)
                .on_delete(ForeignKeyAction::SetNull),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_HISTORY_CREATED_DATE)
            .table(History::Table)
            .col(History::CreatedDate)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_HISTORY_ENTITY)
            .table(History::Table)
            .col(History::EntityId)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_HISTORY_ORG_CREATED_DATE)
            .table(History::Table)
            .col(History::OrganisationId)
            .col(History::CreatedDate)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await?;
    // Create index with 255-char prefix (needed for wallet instance attestation search)
    if manager.supported_db_type() == SupportedDbType::MySql {
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "CREATE INDEX IF NOT EXISTS `{INDEX_HISTORY_METADATA}` ON `history` (`metadata`(255))"
            ))
            .await?;
    } else {
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(INDEX_HISTORY_METADATA)
                    .table(History::Table)
                    .col(History::Metadata)
                    .to_owned(),
            )
            .await?
    }
    Ok(())
}

async fn remote_entity_cache_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(RemoteEntityCache::Table)
        .col(uuid_char(RemoteEntityCache::Id).primary_key())
        .col(timestamp(RemoteEntityCache::CreatedDate, manager))
        .col(timestamp(RemoteEntityCache::LastModified, manager))
        .col(timestamp(RemoteEntityCache::LastUsed, manager))
        .col(timestamp_null(RemoteEntityCache::ExpirationDate, manager))
        .col(string(RemoteEntityCache::Type))
        .col(string_len(RemoteEntityCache::Key, 4096))
        .col(string_null(RemoteEntityCache::MediaType))
        .col(large_blob(RemoteEntityCache::Value, manager))
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_REMOTE_ENTITY_CACHE_TYPE_EXPIRATION_DATE)
            .table(RemoteEntityCache::Table)
            .col(RemoteEntityCache::Type)
            .col(RemoteEntityCache::ExpirationDate)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_REMOTE_ENTITY_CACHE_KEY)
            .unique()
            .table(RemoteEntityCache::Table)
            .col(RemoteEntityCache::Key)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn notification_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(Notification::Table)
        .col(uuid_char(Notification::Id).primary_key())
        .col(timestamp(Notification::CreatedDate, manager))
        .col(timestamp(Notification::NextTryDate, manager))
        .col(string(Notification::Type))
        .col(text(Notification::Url))
        .col(string_null(Notification::HistoryTarget))
        .col(unsigned(Notification::TriesCount))
        .col(large_blob(Notification::Payload, manager))
        .col(uuid_char(Notification::OrganisationId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_NOTIFICATION_ORGANISATION)
                .from_tbl(Notification::Table)
                .from_col(Notification::OrganisationId)
                .to_tbl(Organisation::Table)
                .to_col(Organisation::Id),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_NOTIFICATION_CREATED_DATE)
            .table(Notification::Table)
            .col(Notification::CreatedDate)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_NOTIFICATION_NEXT_TRY_DATE)
            .table(Notification::Table)
            .col(Notification::Type)
            .col(Notification::NextTryDate)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn key_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(Key::Table)
        .col(uuid_char(Key::Id).primary_key())
        .col(timestamp(Key::CreatedDate, manager))
        .col(timestamp(Key::LastModified, manager))
        .col(timestamp_null(Key::DeletedAt, manager))
        .col(string(Key::Name))
        .col(large_blob(Key::PublicKey, manager))
        .col(large_blob_null(Key::KeyReference, manager))
        .col(string(Key::StorageType))
        .col(string(Key::KeyType))
        .col(uuid_char(Key::OrganisationId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_KEY_ORGANISATION)
                .from_tbl(Key::Table)
                .from_col(Key::OrganisationId)
                .to_tbl(Organisation::Table)
                .to_col(Organisation::Id),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_KEY_CREATED_DATE)
            .table(Key::Table)
            .col(Key::CreatedDate)
            .to_owned(),
    ];

    table_with_indexes(table, indexes, manager).await?;

    add_nullable_unique_idx(
        Key::Table,
        Key::DeletedAt,
        INDEX_UNIQUE_KEY_NAME_ORGANISATION_DELETED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![Key::Name, Key::OrganisationId],
            ..Default::default()
        },
        manager,
    )
    .await
}

async fn did_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(Did::Table)
        .col(uuid_char(Did::Id).primary_key())
        .col(timestamp(Did::CreatedDate, manager))
        .col(timestamp(Did::LastModified, manager))
        .col(timestamp_null(Did::DeletedAt, manager))
        .col(string_len(Did::Did, 4000))
        .col(string(Did::Name))
        .col(string(Did::Type))
        .col(string(Did::Method))
        .col(boolean(Did::Deactivated))
        .col(text_null(Did::Log))
        .col(uuid_char_null(Did::OrganisationId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_DID_ORGANISATION)
                .from_tbl(Did::Table)
                .from_col(Did::OrganisationId)
                .to_tbl(Organisation::Table)
                .to_col(Organisation::Id),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_DID_CREATED_DATE)
            .table(Did::Table)
            .col(Did::CreatedDate)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_DID_DID)
            .table(Did::Table)
            .col(Did::Did)
            .to_owned(),
    ];

    table_with_indexes(table, indexes, manager).await?;

    add_nullable_unique_idx(
        Did::Table,
        Did::OrganisationId,
        INDEX_UNIQUE_DID_DID_ORGANISATION,
        NullableIdxOpts {
            non_nullable_columns: vec![Did::Did],
            null_value: Some("no_organisation"),
            ..Default::default()
        },
        manager,
    )
    .await?;

    add_nullable_unique_idx(
        Did::Table,
        Did::DeletedAt,
        INDEX_UNIQUE_DID_NAME_ORGANISATION_DELETED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![Did::Name, Did::OrganisationId],
            ..Default::default()
        },
        manager,
    )
    .await
}

async fn key_did_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(KeyDid::Table)
                .col(uuid_char(KeyDid::KeyId))
                .col(uuid_char(KeyDid::DidId))
                .col(string(KeyDid::Role))
                .primary_key(
                    Index::create()
                        .name("pk-KeyDid")
                        .col(KeyDid::DidId)
                        .col(KeyDid::KeyId)
                        .col(KeyDid::Role)
                        .primary(),
                )
                .col(string_len(KeyDid::Reference, 4000))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_KEY_DID_KEY)
                        .from_tbl(KeyDid::Table)
                        .from_col(KeyDid::KeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_KEY_DID_DID)
                        .from_tbl(KeyDid::Table)
                        .from_col(KeyDid::DidId)
                        .to_tbl(Did::Table)
                        .to_col(Did::Id),
                )
                .to_owned(),
        )
        .await
}

async fn identifier_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(Identifier::Table)
                .col(uuid_char(Identifier::Id).primary_key())
                .col(timestamp(Identifier::CreatedDate, manager))
                .col(timestamp(Identifier::LastModified, manager))
                .col(timestamp_null(Identifier::DeletedAt, manager))
                .col(string(Identifier::Name))
                .col(string(Identifier::Type))
                .col(boolean(Identifier::IsRemote))
                .col(string(Identifier::State))
                .col(uuid_char_null(Identifier::OrganisationId))
                .col(uuid_char_null(Identifier::DidId))
                .col(uuid_char_null(Identifier::KeyId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_IDENTIFIER_ORGANISATION)
                        .from_tbl(Identifier::Table)
                        .from_col(Identifier::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_IDENTIFIER_DID)
                        .from_tbl(Identifier::Table)
                        .from_col(Identifier::DidId)
                        .to_tbl(Did::Table)
                        .to_col(Did::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_IDENTIFIER_KEY)
                        .from_tbl(Identifier::Table)
                        .from_col(Identifier::KeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .to_owned(),
        )
        .await?;
    add_nullable_unique_idx(
        Identifier::Table,
        Identifier::DeletedAt,
        INDEX_UNIQUE_IDENTIFIER_NAME_ORGANISATION_DELETED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![Identifier::Name, Identifier::OrganisationId],
            ..Default::default()
        },
        manager,
    )
    .await
}

async fn certificate_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(Certificate::Table)
        .col(uuid_char(Certificate::Id).primary_key())
        .col(timestamp(Certificate::CreatedDate, manager))
        .col(timestamp(Certificate::LastModified, manager))
        .col(timestamp_null(Certificate::DeletedAt, manager))
        .col(timestamp_seconds(Certificate::ExpiryDate, manager))
        .col(string(Certificate::Name))
        .col(text(Certificate::Chain))
        .col(string(Certificate::Fingerprint))
        .col(string(Certificate::State))
        .col(string_null(Certificate::Roles))
        .col(uuid_char_null(Certificate::OrganisationId))
        .col(uuid_char(Certificate::IdentifierId))
        .col(uuid_char_null(Certificate::KeyId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CERTIFICATE_ORGANISATION)
                .from_tbl(Certificate::Table)
                .from_col(Certificate::OrganisationId)
                .to_tbl(Organisation::Table)
                .to_col(Organisation::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CERTIFICATE_IDENTIFIER)
                .from_tbl(Certificate::Table)
                .from_col(Certificate::IdentifierId)
                .to_tbl(Identifier::Table)
                .to_col(Identifier::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CERTIFICATE_KEY)
                .from_tbl(Certificate::Table)
                .from_col(Certificate::KeyId)
                .to_tbl(Key::Table)
                .to_col(Key::Id),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_CERTIFICATE_NAME_EXPIRY_DATE_IDENTIFIER)
            .table(Certificate::Table)
            .col(Certificate::Name)
            .col(Certificate::ExpiryDate)
            .col(Certificate::IdentifierId)
            .unique()
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await?;
    add_nullable_unique_idx(
        Certificate::Table,
        Certificate::DeletedAt,
        INDEX_UNIQUE_CERTIFICATE_FINGERPRINT_ORGANISATION_DELETED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![Certificate::Fingerprint, Certificate::OrganisationId],
            ..Default::default()
        },
        manager,
    )
    .await
}

async fn identifier_trust_information_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(IdentifierTrustInformation::Table)
        .col(uuid_char(IdentifierTrustInformation::Id).primary_key())
        .col(timestamp(IdentifierTrustInformation::CreatedDate, manager))
        .col(timestamp(IdentifierTrustInformation::LastModified, manager))
        .col(timestamp_null(
            IdentifierTrustInformation::ValidFrom,
            manager,
        ))
        .col(timestamp_null(IdentifierTrustInformation::ValidTo, manager))
        .col(string_null(IdentifierTrustInformation::IntendedUse))
        .col(string_len_null(
            IdentifierTrustInformation::AllowedIssuanceTypes,
            512,
        ))
        .col(string_len_null(
            IdentifierTrustInformation::AllowedVerificationTypes,
            512,
        ))
        .col(uuid_char(IdentifierTrustInformation::IdentifierId))
        .col(uuid_char(IdentifierTrustInformation::BlobId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_IDENTIFIER_TRUST_INFORMATION_IDENTIFIER)
                .from_tbl(IdentifierTrustInformation::Table)
                .from_col(IdentifierTrustInformation::IdentifierId)
                .to_tbl(Identifier::Table)
                .to_col(Identifier::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_IDENTIFIER_TRUST_INFORMATION_BLOB)
                .from_tbl(IdentifierTrustInformation::Table)
                .from_col(IdentifierTrustInformation::BlobId)
                .to_tbl(BlobStorage::Table)
                .to_col(BlobStorage::Id),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_IDENTIFIER_TRUST_INFORMATION_IDENTIFIER_BLOB)
            .unique()
            .table(IdentifierTrustInformation::Table)
            .col(IdentifierTrustInformation::IdentifierId)
            .col(IdentifierTrustInformation::BlobId)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn credential_schema_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(CredentialSchema::Table)
        .col(uuid_char(CredentialSchema::Id).primary_key())
        .col(timestamp(CredentialSchema::CreatedDate, manager))
        .col(timestamp(CredentialSchema::LastModified, manager))
        .col(timestamp_null(CredentialSchema::DeletedAt, manager))
        .col(string(CredentialSchema::Name))
        .col(string(CredentialSchema::Format))
        .col(string_null(CredentialSchema::RevocationMethod))
        .col(string(CredentialSchema::SchemaId))
        .col(string(CredentialSchema::LayoutType))
        .col(json_null(CredentialSchema::LayoutProperties))
        .col(string(CredentialSchema::ImportedSourceUrl))
        .col(boolean(CredentialSchema::AllowSuspension))
        .col(boolean(CredentialSchema::RequiresWalletInstanceAttestation))
        .col(string_null(CredentialSchema::KeyStorageSecurity))
        .col(string_null(CredentialSchema::TransactionCodeType))
        .col(unsigned_null(CredentialSchema::TransactionCodeLength))
        .col(string_len_null(
            CredentialSchema::TransactionCodeDescription,
            300,
        ))
        .col(uuid_char(CredentialSchema::OrganisationId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CREDENTIAL_SCHEMA_ORGANISATION)
                .from_tbl(CredentialSchema::Table)
                .from_col(CredentialSchema::OrganisationId)
                .to_tbl(Organisation::Table)
                .to_col(Organisation::Id),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_CREDENTIAL_SCHEMA_CREATED_DATE)
            .table(CredentialSchema::Table)
            .col(CredentialSchema::CreatedDate)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await?;
    add_nullable_unique_idx(
        CredentialSchema::Table,
        CredentialSchema::DeletedAt,
        INDEX_UNIQUE_CREDENTIAL_SCHEMA_NAME_ORGANISATION_DELETED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![CredentialSchema::Name, CredentialSchema::OrganisationId],
            ..Default::default()
        },
        manager,
    )
    .await?;
    add_nullable_unique_idx(
        CredentialSchema::Table,
        CredentialSchema::DeletedAt,
        INDEX_UNIQUE_CREDENTIAL_SCHEMA_SCHEMA_ID_ORGANISATION_DELETED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![
                CredentialSchema::OrganisationId,
                CredentialSchema::SchemaId,
            ],
            ..Default::default()
        },
        manager,
    )
    .await
}

async fn claim_schema_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(ClaimSchema::Table)
                .col(uuid_char(ClaimSchema::Id).primary_key())
                .col(timestamp(ClaimSchema::CreatedDate, manager))
                .col(timestamp(ClaimSchema::LastModified, manager))
                .col(string(ClaimSchema::Key))
                .col(string(ClaimSchema::Datatype))
                .col(boolean(ClaimSchema::Array))
                .col(boolean(ClaimSchema::Required))
                .col(boolean(ClaimSchema::Metadata))
                .col(unsigned(ClaimSchema::Order))
                .col(uuid_char(ClaimSchema::CredentialSchemaId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CLAIM_SCHEMA_CREDENTIAL_SCHEMA)
                        .from_tbl(ClaimSchema::Table)
                        .from_col(ClaimSchema::CredentialSchemaId)
                        .to_tbl(CredentialSchema::Table)
                        .to_col(CredentialSchema::Id),
                )
                .to_owned(),
        )
        .await
}

async fn proof_schema_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(ProofSchema::Table)
        .col(uuid_char(ProofSchema::Id).primary_key())
        .col(timestamp(ProofSchema::CreatedDate, manager))
        .col(timestamp(ProofSchema::LastModified, manager))
        .col(timestamp_null(ProofSchema::DeletedAt, manager))
        .col(string(ProofSchema::Name))
        .col(unsigned(ProofSchema::ExpireDuration))
        .col(text_null(ProofSchema::ImportedSourceUrl))
        .col(uuid_char(ProofSchema::OrganisationId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_PROOF_SCHEMA_ORGANISATION)
                .from_tbl(ProofSchema::Table)
                .from_col(ProofSchema::OrganisationId)
                .to_tbl(Organisation::Table)
                .to_col(Organisation::Id),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_PROOF_SCHEMA_CREATED_DATE)
            .table(ProofSchema::Table)
            .col(ProofSchema::CreatedDate)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await?;
    add_nullable_unique_idx(
        ProofSchema::Table,
        ProofSchema::DeletedAt,
        INDEX_UNIQUE_PROOF_SCHEMA_NAME_ORGANISATION_DELETED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![ProofSchema::Name, ProofSchema::OrganisationId],
            ..Default::default()
        },
        manager,
    )
    .await
}

async fn proof_input_schema_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(ProofInputSchema::Table)
                .col(
                    big_integer(ProofInputSchema::Id)
                        .auto_increment()
                        .primary_key(),
                )
                .col(timestamp(ProofInputSchema::CreatedDate, manager))
                .col(timestamp(ProofInputSchema::LastModified, manager))
                .col(unsigned(ProofInputSchema::Order))
                .col(uuid_char(ProofInputSchema::CredentialSchema))
                .col(uuid_char(ProofInputSchema::ProofSchema))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_PROOF_INPUT_SCHEMA_CREDENTIAL_SCHEMA)
                        .from_tbl(ProofInputSchema::Table)
                        .from_col(ProofInputSchema::CredentialSchema)
                        .to_tbl(CredentialSchema::Table)
                        .to_col(CredentialSchema::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_PROOF_INPUT_SCHEMA_PROOF_SCHEMA)
                        .from_tbl(ProofInputSchema::Table)
                        .from_col(ProofInputSchema::ProofSchema)
                        .to_tbl(ProofSchema::Table)
                        .to_col(ProofSchema::Id),
                )
                .to_owned(),
        )
        .await
}

async fn proof_input_claim_schema_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(ProofInputClaimSchema::Table)
                .col(uuid_char(ProofInputClaimSchema::ClaimSchemaId))
                .col(big_integer(ProofInputClaimSchema::ProofInputSchemaId))
                .primary_key(
                    Index::create()
                        .name("pk-ProofInputClaimSchema")
                        .col(ProofInputClaimSchema::ClaimSchemaId)
                        .col(ProofInputClaimSchema::ProofInputSchemaId)
                        .primary(),
                )
                .col(unsigned(ProofInputClaimSchema::Order))
                .col(boolean(ProofInputClaimSchema::Required))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_PROOF_INPUT_CLAIM_SCHEMA_CLAIM_SCHEMA)
                        .from_tbl(ProofInputClaimSchema::Table)
                        .from_col(ProofInputClaimSchema::ClaimSchemaId)
                        .to_tbl(ClaimSchema::Table)
                        .to_col(ClaimSchema::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_PROOF_INPUT_CLAIM_SCHEMA_PROOF_INPUT_SCHEMA)
                        .from_tbl(ProofInputClaimSchema::Table)
                        .from_col(ProofInputClaimSchema::ProofInputSchemaId)
                        .to_tbl(ProofInputSchema::Table)
                        .to_col(ProofInputSchema::Id),
                )
                .to_owned(),
        )
        .await
}

async fn interaction_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(Interaction::Table)
        .col(uuid_char(Interaction::Id).primary_key())
        .col(timestamp(Interaction::CreatedDate, manager))
        .col(timestamp(Interaction::LastModified, manager))
        .col(timestamp_null(Interaction::ExpiresAt, manager))
        .col(large_blob_null(Interaction::Data, manager))
        .col(string(Interaction::InteractionType))
        .col(uuid_char(Interaction::OrganisationId))
        .col(uuid_char_null(Interaction::NonceId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_INTERACTION_ORGANISATION)
                .from_tbl(Interaction::Table)
                .from_col(Interaction::OrganisationId)
                .to_tbl(Organisation::Table)
                .to_col(Organisation::Id),
        )
        .to_owned();

    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_INTERACTION_NONCE_ID)
            .table(Interaction::Table)
            .col(Interaction::NonceId)
            .unique()
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_INTERACTION_EXPIRES_AT)
            .table(Interaction::Table)
            .col(Interaction::ExpiresAt)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn credential_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(Credential::Table)
        .col(uuid_char(Credential::Id).primary_key())
        .col(timestamp(Credential::CreatedDate, manager))
        .col(timestamp(Credential::LastModified, manager))
        .col(timestamp_null(Credential::IssuanceDate, manager))
        .col(timestamp_null(Credential::DeletedAt, manager))
        .col(timestamp_null(Credential::SuspendEndDate, manager))
        .col(string(Credential::Protocol))
        .col(string(Credential::Role))
        .col(string(Credential::State))
        .col(string_null(Credential::Profile))
        .col(string_len_null(Credential::RedirectUri, 1000))
        .col(text_null(Credential::WebhookUrl))
        .col(uuid_char(Credential::CredentialSchemaId))
        .col(uuid_char_null(Credential::InteractionId))
        .col(uuid_char_null(Credential::HolderIdentifierId))
        .col(uuid_char_null(Credential::KeyId))
        .col(uuid_char_null(Credential::IssuerIdentifierId))
        .col(uuid_char_null(Credential::IssuerCertificateId))
        .col(uuid_char_null(Credential::CredentialBlobId))
        .col(uuid_char_null(Credential::WalletInstanceAttestationBlobId))
        .col(uuid_char_null(Credential::WalletUnitAttestationBlobId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CREDENTIAL_CREDENTIAL_SCHEMA)
                .from_tbl(Credential::Table)
                .from_col(Credential::CredentialSchemaId)
                .to_tbl(CredentialSchema::Table)
                .to_col(CredentialSchema::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CREDENTIAL_INTERACTION)
                .from_tbl(Credential::Table)
                .from_col(Credential::InteractionId)
                .to_tbl(Interaction::Table)
                .to_col(Interaction::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CREDENTIAL_HOLDER_IDENTIFIER)
                .from_tbl(Credential::Table)
                .from_col(Credential::HolderIdentifierId)
                .to_tbl(Identifier::Table)
                .to_col(Identifier::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CREDENTIAL_KEY)
                .from_tbl(Credential::Table)
                .from_col(Credential::KeyId)
                .to_tbl(Key::Table)
                .to_col(Key::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CREDENTIAL_ISSUER_IDENTIFIER)
                .from_tbl(Credential::Table)
                .from_col(Credential::IssuerIdentifierId)
                .to_tbl(Identifier::Table)
                .to_col(Identifier::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CREDENTIAL_ISSUER_CERTIFICATE)
                .from_tbl(Credential::Table)
                .from_col(Credential::IssuerCertificateId)
                .to_tbl(Certificate::Table)
                .to_col(Certificate::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CREDENTIAL_CREDENTIAL_BLOB)
                .from_tbl(Credential::Table)
                .from_col(Credential::CredentialBlobId)
                .to_tbl(BlobStorage::Table)
                .to_col(BlobStorage::Id)
                .on_delete(ForeignKeyAction::SetNull),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CREDENTIAL_WALLET_INSTANCE_ATTESTATION_BLOB)
                .from_tbl(Credential::Table)
                .from_col(Credential::WalletInstanceAttestationBlobId)
                .to_tbl(BlobStorage::Table)
                .to_col(BlobStorage::Id)
                .on_delete(ForeignKeyAction::SetNull),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_CREDENTIAL_WALLET_UNIT_ATTESTATION_BLOB)
                .from_tbl(Credential::Table)
                .from_col(Credential::WalletUnitAttestationBlobId)
                .to_tbl(BlobStorage::Table)
                .to_col(BlobStorage::Id)
                .on_delete(ForeignKeyAction::SetNull),
        )
        .to_owned();

    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_CREDENTIAL_LIST)
            .table(Credential::Table)
            .col(Credential::DeletedAt)
            .col(Credential::Role)
            .col(Credential::CreatedDate)
            .col(Credential::Id)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_CREDENTIAL_CREATED_DATE)
            .table(Credential::Table)
            .col(Credential::CreatedDate)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_CREDENTIAL_DELETED_AT)
            .table(Credential::Table)
            .col(Credential::DeletedAt)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_CREDENTIAL_ROLE)
            .table(Credential::Table)
            .col(Credential::Role)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_CREDENTIAL_STATE)
            .table(Credential::Table)
            .col(Credential::State)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_CREDENTIAL_SUSPEND_END_DATE)
            .table(Credential::Table)
            .col(Credential::SuspendEndDate)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn claim_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(Claim::Table)
                .col(uuid_char(Claim::Id).primary_key())
                .col(timestamp(Claim::CreatedDate, manager))
                .col(timestamp(Claim::LastModified, manager))
                .col(large_blob_null(Claim::Value, manager))
                .col(string(Claim::Path))
                .col(boolean(Claim::SelectivelyDisclosable))
                .col(uuid_char(Claim::ClaimSchemaId))
                .col(uuid_char(Claim::CredentialId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CLAIM_CLAIM_SCHEMA)
                        .from_tbl(Claim::Table)
                        .from_col(Claim::ClaimSchemaId)
                        .to_tbl(ClaimSchema::Table)
                        .to_col(ClaimSchema::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CLAIM_CREDENTIAL)
                        .from_tbl(Claim::Table)
                        .from_col(Claim::CredentialId)
                        .to_tbl(Credential::Table)
                        .to_col(Credential::Id),
                )
                .to_owned(),
        )
        .await
}

async fn revocation_list_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let mut table = Table::create()
        .if_not_exists()
        .table(RevocationList::Table)
        .col(uuid_char(RevocationList::Id).primary_key())
        .col(timestamp(RevocationList::CreatedDate, manager))
        .col(timestamp(RevocationList::LastModified, manager))
        .col(large_blob(RevocationList::FormattedList, manager))
        .col(string(RevocationList::Purpose))
        .col(string(RevocationList::Format))
        .col(string(RevocationList::Type))
        .col(uuid_char(RevocationList::IssuerIdentifierId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_REVOCATION_LIST_IDENTIFIER)
                .from_tbl(RevocationList::Table)
                .from_col(RevocationList::IssuerIdentifierId)
                .to_tbl(Identifier::Table)
                .to_col(Identifier::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_REVOCATION_LIST_CERTIFICATE)
                .from_tbl(RevocationList::Table)
                .from_col(RevocationList::IssuerCertificateId)
                .to_tbl(Certificate::Table)
                .to_col(Certificate::Id),
        )
        .to_owned();
    if manager.supported_db_type() == SupportedDbType::MySql {
        // Needs varchar type because of `COALESCE` for the unique index on nullable column
        table.col(string_len_null(RevocationList::IssuerCertificateId, 36));
    } else {
        table.col(uuid_char_null(RevocationList::IssuerCertificateId));
    }
    manager.create_table(table).await?;
    add_nullable_unique_idx(
        RevocationList::Table,
        RevocationList::IssuerCertificateId,
        INDEX_UNIQUE_REVOCATION_LIST_IDENTIFIER_CERTIFICATE_PURPOSE_TYPE,
        NullableIdxOpts {
            non_nullable_columns: vec![
                RevocationList::IssuerIdentifierId,
                RevocationList::Purpose,
                RevocationList::Type,
            ],
            null_value: Some("no_certificate"),
            nullable_column_index_pos: Some(1),
            materialized_column_size_limit: None,
        },
        manager,
    )
    .await
}

async fn revocation_list_entry_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(RevocationListEntry::Table)
        .col(uuid_char(RevocationListEntry::Id).primary_key())
        .col(timestamp(RevocationListEntry::CreatedDate, manager))
        .col(timestamp(RevocationListEntry::LastModified, manager))
        .col(unsigned_null(RevocationListEntry::Index))
        .col(string(RevocationListEntry::State))
        .col(string(RevocationListEntry::Type))
        .col(string_null(RevocationListEntry::SignatureType))
        .col(var_binary_null(RevocationListEntry::Serial, 20))
        .col(uuid_char(RevocationListEntry::RevocationListId))
        .col(uuid_char_null(RevocationListEntry::CredentialId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_REVOCATION_LIST_ENTRY_REVOCATION_LIST)
                .from_tbl(RevocationListEntry::Table)
                .from_col(RevocationListEntry::RevocationListId)
                .to_tbl(RevocationList::Table)
                .to_col(RevocationList::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_REVOCATION_LIST_ENTRY_CREDENTIAL)
                .from_tbl(RevocationListEntry::Table)
                .from_col(RevocationListEntry::CredentialId)
                .to_tbl(Credential::Table)
                .to_col(Credential::Id),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_REVOCATION_LIST_ENTRY_REVOCATION_LIST_INDEX)
            .unique()
            .table(RevocationListEntry::Table)
            .col(RevocationListEntry::RevocationListId)
            .col(RevocationListEntry::Index)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_REVOCATION_LIST_ENTRY_REVOCATION_LIST_SERIAL)
            .unique()
            .table(RevocationListEntry::Table)
            .col(RevocationListEntry::RevocationListId)
            .col(RevocationListEntry::Serial)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn validity_credential_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(ValidityCredential::Table)
                .col(uuid_char(ValidityCredential::Id).primary_key())
                .col(timestamp(ValidityCredential::CreatedDate, manager))
                .col(large_blob(ValidityCredential::Credential, manager))
                .col(string(ValidityCredential::Type))
                .col(uuid_char(ValidityCredential::CredentialId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_VALIDITY_CREDENTIAL_CREDENTIAL)
                        .from_tbl(ValidityCredential::Table)
                        .from_col(ValidityCredential::CredentialId)
                        .to_tbl(Credential::Table)
                        .to_col(Credential::Id),
                )
                .to_owned(),
        )
        .await
}

async fn proof_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(Proof::Table)
        .col(uuid_char(Proof::Id).primary_key())
        .col(timestamp(Proof::CreatedDate, manager))
        .col(timestamp(Proof::LastModified, manager))
        .col(timestamp_null(Proof::RequestedDate, manager))
        .col(timestamp_null(Proof::CompletedDate, manager))
        .col(string(Proof::Protocol))
        .col(string(Proof::Role))
        .col(string(Proof::State))
        .col(string(Proof::Transport))
        .col(string_null(Proof::Profile))
        .col(string_null(Proof::Engagement).default("QR_CODE"))
        .col(string_len_null(Proof::RedirectUri, 1000))
        .col(text_null(Proof::WebhookUrl))
        .col(uuid_char_null(Proof::ProofSchemaId))
        .col(uuid_char_null(Proof::InteractionId))
        .col(uuid_char_null(Proof::VerifierIdentifierId))
        .col(uuid_char_null(Proof::VerifierCertificateId))
        .col(uuid_char_null(Proof::VerifierKeyId))
        .col(uuid_char_null(Proof::ProofBlobId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_PROOF_PROOF_SCHEMA)
                .from_tbl(Proof::Table)
                .from_col(Proof::ProofSchemaId)
                .to_tbl(ProofSchema::Table)
                .to_col(ProofSchema::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_PROOF_INTERACTION)
                .from_tbl(Proof::Table)
                .from_col(Proof::InteractionId)
                .to_tbl(Interaction::Table)
                .to_col(Interaction::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_PROOF_VERIFIER_IDENTIFIER)
                .from_tbl(Proof::Table)
                .from_col(Proof::VerifierIdentifierId)
                .to_tbl(Identifier::Table)
                .to_col(Identifier::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_PROOF_VERIFIER_CERTIFICATE)
                .from_tbl(Proof::Table)
                .from_col(Proof::VerifierCertificateId)
                .to_tbl(Certificate::Table)
                .to_col(Certificate::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_PROOF_VERIFIER_KEY)
                .from_tbl(Proof::Table)
                .from_col(Proof::VerifierKeyId)
                .to_tbl(Key::Table)
                .to_col(Key::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_PROOF_PROOF_BLOB)
                .from_tbl(Proof::Table)
                .from_col(Proof::ProofBlobId)
                .to_tbl(BlobStorage::Table)
                .to_col(BlobStorage::Id)
                .on_delete(ForeignKeyAction::SetNull),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_PROOF_CREATED_DATE)
            .table(Proof::Table)
            .col(Proof::CreatedDate)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn proof_claim_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(ProofClaim::Table)
                .col(uuid_char(ProofClaim::ProofId))
                .col(uuid_char(ProofClaim::ClaimId))
                .primary_key(
                    Index::create()
                        .name("pk-ProofClaim")
                        .col(ProofClaim::ProofId)
                        .col(ProofClaim::ClaimId)
                        .primary(),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_PROOF_CLAIM_CLAIM)
                        .from_tbl(ProofClaim::Table)
                        .from_col(ProofClaim::ClaimId)
                        .to_tbl(Claim::Table)
                        .to_col(Claim::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_PROOF_CLAIM_PROOF)
                        .from_tbl(ProofClaim::Table)
                        .from_col(ProofClaim::ProofId)
                        .to_tbl(Proof::Table)
                        .to_col(Proof::Id),
                )
                .to_owned(),
        )
        .await
}

async fn wallet_instance_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(WalletInstance::Table)
        .col(uuid_char(WalletInstance::Id).primary_key())
        .col(timestamp(WalletInstance::CreatedDate, manager))
        .col(timestamp(WalletInstance::LastModified, manager))
        .col(timestamp_null(WalletInstance::LastIssuance, manager))
        .col(string(WalletInstance::Name))
        .col(string(WalletInstance::Os))
        .col(string(WalletInstance::Status))
        .col(string_null(WalletInstance::Nonce))
        .col(string(WalletInstance::WalletProviderType))
        .col(string(WalletInstance::WalletProviderName))
        .col(text_null(WalletInstance::AuthenticationKeyJwk))
        .col(uuid_char(WalletInstance::OrganisationId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_WALLET_INSTANCE_ORGANISATION)
                .from_tbl(WalletInstance::Table)
                .from_col(WalletInstance::OrganisationId)
                .to_tbl(Organisation::Table)
                .to_col(Organisation::Id),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_WALLET_INSTANCE_AUTHENTICATION_KEY_ORGANISATION)
            .unique()
            .table(WalletInstance::Table)
            .col(WalletInstance::AuthenticationKeyJwk)
            .col(WalletInstance::OrganisationId)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn wallet_instance_attested_key_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(WalletInstanceAttestedKey::Table)
                .col(uuid_char(WalletInstanceAttestedKey::Id).primary_key())
                .col(timestamp(WalletInstanceAttestedKey::CreatedDate, manager))
                .col(timestamp(WalletInstanceAttestedKey::LastModified, manager))
                .col(timestamp(
                    WalletInstanceAttestedKey::ExpirationDate,
                    manager,
                ))
                .col(text(WalletInstanceAttestedKey::PublicKeyJwk))
                .col(uuid_char(WalletInstanceAttestedKey::WalletInstanceId))
                .col(uuid_char_null(
                    WalletInstanceAttestedKey::RevocationListEntryId,
                ))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_WALLET_INSTANCE_ATTESTED_KEY_WALLET_INSTANCE)
                        .from_tbl(WalletInstanceAttestedKey::Table)
                        .from_col(WalletInstanceAttestedKey::WalletInstanceId)
                        .to_tbl(WalletInstance::Table)
                        .to_col(WalletInstance::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_WALLET_INSTANCE_ATTESTED_KEY_REVOCATION_LIST_ENTRY)
                        .from_tbl(WalletInstanceAttestedKey::Table)
                        .from_col(WalletInstanceAttestedKey::RevocationListEntryId)
                        .to_tbl(RevocationListEntry::Table)
                        .to_col(RevocationListEntry::Id),
                )
                .to_owned(),
        )
        .await
}

async fn holder_wallet_instance_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(HolderWalletInstance::Table)
        .col(uuid_char(HolderWalletInstance::Id).primary_key())
        .col(timestamp(HolderWalletInstance::CreatedDate, manager))
        .col(timestamp(HolderWalletInstance::LastModified, manager))
        .col(string(HolderWalletInstance::WalletProviderUrl))
        .col(string(HolderWalletInstance::WalletProviderName))
        .col(string(HolderWalletInstance::WalletProviderType))
        .col(string(HolderWalletInstance::Status))
        .col(uuid_char(HolderWalletInstance::ProviderWalletUnitId))
        .col(uuid_char(HolderWalletInstance::OrganisationId))
        .col(uuid_char_null(HolderWalletInstance::AuthenticationKeyId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_HOLDER_WALLET_INSTANCE_ORGANISATION)
                .from_tbl(HolderWalletInstance::Table)
                .from_col(HolderWalletInstance::OrganisationId)
                .to_tbl(Organisation::Table)
                .to_col(Organisation::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_HOLDER_WALLET_INSTANCE_KEY)
                .from_tbl(HolderWalletInstance::Table)
                .from_col(HolderWalletInstance::AuthenticationKeyId)
                .to_tbl(Key::Table)
                .to_col(Key::Id),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_HOLDER_WALLET_INSTANCE_ORGANISATION)
            .unique()
            .table(HolderWalletInstance::Table)
            .col(HolderWalletInstance::OrganisationId)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn wallet_instance_attestation_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(WalletInstanceAttestation::Table)
        .col(uuid_char(WalletInstanceAttestation::Id).primary_key())
        .col(timestamp(WalletInstanceAttestation::CreatedDate, manager))
        .col(timestamp(WalletInstanceAttestation::LastModified, manager))
        .col(timestamp(
            WalletInstanceAttestation::ExpirationDate,
            manager,
        ))
        .col(string_null(WalletInstanceAttestation::RevocationListUrl))
        .col(unsigned_null(
            WalletInstanceAttestation::RevocationListIndex,
        ))
        .col(large_blob(WalletInstanceAttestation::Attestation, manager))
        .col(uuid_char(WalletInstanceAttestation::HolderWalletUnitId))
        .col(uuid_char(WalletInstanceAttestation::AttestedKeyId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_WALLET_INSTANCE_ATTESTATION_HOLDER_WALLET_INSTANCE)
                .from_tbl(WalletInstanceAttestation::Table)
                .from_col(WalletInstanceAttestation::HolderWalletUnitId)
                .to_tbl(HolderWalletInstance::Table)
                .to_col(HolderWalletInstance::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_WALLET_INSTANCE_ATTESTATION_KEY)
                .from_tbl(WalletInstanceAttestation::Table)
                .from_col(WalletInstanceAttestation::AttestedKeyId)
                .to_tbl(Key::Table)
                .to_col(Key::Id),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_WALLET_INSTANCE_ATTESTATION_KEY)
            .unique()
            .table(WalletInstanceAttestation::Table)
            .col(WalletInstanceAttestation::AttestedKeyId)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn verifier_instance_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(VerifierInstance::Table)
        .col(uuid_char(VerifierInstance::Id).primary_key())
        .col(timestamp(VerifierInstance::CreatedDate, manager))
        .col(timestamp(VerifierInstance::LastModified, manager))
        .col(string(VerifierInstance::ProviderUrl))
        .col(string(VerifierInstance::ProviderType))
        .col(string(VerifierInstance::ProviderName))
        .col(uuid_char(VerifierInstance::OrganisationId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_VERIFIER_INSTANCE_ORGANISATION)
                .from_tbl(VerifierInstance::Table)
                .from_col(VerifierInstance::OrganisationId)
                .to_tbl(Organisation::Table)
                .to_col(Organisation::Id),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_VERIFIER_INSTANCE_ORGANISATION)
            .unique()
            .table(VerifierInstance::Table)
            .col(VerifierInstance::OrganisationId)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn trust_list_publication_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(TrustListPublication::Table)
                .col(uuid_char(TrustListPublication::Id).primary_key())
                .col(timestamp(TrustListPublication::CreatedDate, manager))
                .col(timestamp(TrustListPublication::LastModified, manager))
                .col(timestamp_null(TrustListPublication::DeactivatedAt, manager))
                .col(string(TrustListPublication::Role))
                .col(string(TrustListPublication::Type))
                .col(text(TrustListPublication::Name))
                .col(large_blob(TrustListPublication::Metadata, manager))
                .col(large_blob(TrustListPublication::Content, manager))
                .col(unsigned(TrustListPublication::SequenceNumber))
                .col(uuid_char(TrustListPublication::OrganisationId))
                .col(uuid_char(TrustListPublication::IdentifierId))
                .col(uuid_char_null(TrustListPublication::CertificateId))
                .col(uuid_char_null(TrustListPublication::KeyId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_TRUST_LIST_PUBLICATION_ORGANISATION)
                        .from_tbl(TrustListPublication::Table)
                        .from_col(TrustListPublication::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_TRUST_LIST_PUBLICATION_IDENTIFIER)
                        .from_tbl(TrustListPublication::Table)
                        .from_col(TrustListPublication::IdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_TRUST_LIST_PUBLICATION_CERTIFICATE)
                        .from_tbl(TrustListPublication::Table)
                        .from_col(TrustListPublication::CertificateId)
                        .to_tbl(Certificate::Table)
                        .to_col(Certificate::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_TRUST_LIST_PUBLICATION_KEY)
                        .from_tbl(TrustListPublication::Table)
                        .from_col(TrustListPublication::KeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .to_owned(),
        )
        .await?;
    add_nullable_unique_idx(
        TrustListPublication::Table,
        TrustListPublication::DeactivatedAt,
        INDEX_UNIQUE_TRUST_LIST_PUBLICATION_NAME_ORGANISATION_DEACTIVATED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![
                TrustListPublication::Name,
                TrustListPublication::OrganisationId,
            ],
            null_value: Some("not_deactivated"),
            ..Default::default()
        },
        manager,
    )
    .await
}

async fn trust_entry_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(TrustEntry::Table)
        .col(uuid_char(TrustEntry::Id).primary_key())
        .col(timestamp(TrustEntry::CreatedDate, manager))
        .col(timestamp(TrustEntry::LastModified, manager))
        .col(string(TrustEntry::State))
        .col(large_blob(TrustEntry::Metadata, manager))
        .col(uuid_char(TrustEntry::TrustListPublicationId))
        .col(uuid_char(TrustEntry::IdentifierId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_TRUST_ENTRY_PUBLICATION)
                .from_tbl(TrustEntry::Table)
                .from_col(TrustEntry::TrustListPublicationId)
                .to_tbl(TrustListPublication::Table)
                .to_col(TrustListPublication::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_TRUST_ENTRY_IDENTIFIER)
                .from_tbl(TrustEntry::Table)
                .from_col(TrustEntry::IdentifierId)
                .to_tbl(Identifier::Table)
                .to_col(Identifier::Id),
        )
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_TRUST_ENTRY_IDENTIFIER_PUBLICATION)
            .unique()
            .table(TrustEntry::Table)
            .col(TrustEntry::IdentifierId)
            .col(TrustEntry::TrustListPublicationId)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn trust_collection_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(TrustCollection::Table)
                .col(uuid_char(TrustCollection::Id).primary_key())
                .col(timestamp(TrustCollection::CreatedDate, manager))
                .col(timestamp(TrustCollection::LastModified, manager))
                .col(timestamp_null(TrustCollection::DeactivatedAt, manager))
                .col(string(TrustCollection::Name))
                .col(text_null(TrustCollection::RemoteTrustCollectionUrl))
                .col(uuid_char(TrustCollection::OrganisationId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_TRUST_COLLECTION_ORGANISATION)
                        .from_tbl(TrustCollection::Table)
                        .from_col(TrustCollection::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;
    add_nullable_unique_idx(
        TrustCollection::Table,
        TrustCollection::DeactivatedAt,
        INDEX_UNIQUE_TRUST_COLLECTION_NAME_ORGANISATION_DEACTIVATED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![TrustCollection::Name, TrustCollection::OrganisationId],
            null_value: Some("not_deactivated"),
            ..Default::default()
        },
        manager,
    )
    .await
}

async fn trust_list_subscription_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(TrustListSubscription::Table)
                .col(uuid_char(TrustListSubscription::Id).primary_key())
                .col(timestamp(TrustListSubscription::CreatedDate, manager))
                .col(timestamp(TrustListSubscription::LastModified, manager))
                .col(timestamp_null(
                    TrustListSubscription::DeactivatedAt,
                    manager,
                ))
                .col(string(TrustListSubscription::Role))
                .col(string(TrustListSubscription::Type))
                .col(string(TrustListSubscription::State))
                .col(string(TrustListSubscription::Name))
                .col(text(TrustListSubscription::Reference))
                .col(uuid_char(TrustListSubscription::TrustCollectionId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_TRUST_LIST_SUBSCRIPTION_COLLECTION)
                        .from_tbl(TrustListSubscription::Table)
                        .from_col(TrustListSubscription::TrustCollectionId)
                        .to_tbl(TrustCollection::Table)
                        .to_col(TrustCollection::Id),
                )
                .to_owned(),
        )
        .await?;
    add_nullable_unique_idx(
        TrustListSubscription::Table,
        TrustListSubscription::DeactivatedAt,
        INDEX_UNIQUE_TRUST_LIST_SUBSCRIPTION_NAME_COLLECTION_DEACTIVATED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![
                TrustListSubscription::Name,
                TrustListSubscription::TrustCollectionId,
            ],

            null_value: Some("not_deactivated"),
            ..Default::default()
        },
        manager,
    )
    .await?;
    add_nullable_unique_idx(
        TrustListSubscription::Table,
        TrustListSubscription::DeactivatedAt,
        INDEX_UNIQUE_TRUST_LIST_SUBSCRIPTION_REFERENCE_COLLECTION_DEACTIVATED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![
                TrustListSubscription::Reference,
                TrustListSubscription::TrustCollectionId,
            ],
            null_value: Some("not_deactivated"),
            ..Default::default()
        },
        manager,
    )
    .await
}

async fn trust_anchor_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(TrustAnchor::Table)
        .col(uuid_char(TrustAnchor::Id).primary_key())
        .col(timestamp(TrustAnchor::CreatedDate, manager))
        .col(timestamp(TrustAnchor::LastModified, manager))
        .col(text(TrustAnchor::Name))
        .col(string(TrustAnchor::Type))
        .col(boolean(TrustAnchor::IsPublisher))
        .col(text(TrustAnchor::PublisherReference))
        .to_owned();
    let indexes = vec![
        Index::create()
            .if_not_exists()
            .name(INDEX_UNIQUE_TRUST_ANCHOR_NAME)
            .unique()
            .table(TrustAnchor::Table)
            .col(TrustAnchor::Name)
            .to_owned(),
    ];
    table_with_indexes(table, indexes, manager).await
}

async fn trust_entity_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let table = Table::create()
        .if_not_exists()
        .table(TrustEntity::Table)
        .col(uuid_char(TrustEntity::Id).primary_key())
        .col(timestamp(TrustEntity::CreatedDate, manager))
        .col(timestamp(TrustEntity::LastModified, manager))
        .col(timestamp_null(TrustEntity::DeactivatedAt, manager))
        .col(text(TrustEntity::Name))
        .col(large_blob_null(TrustEntity::Logo, manager))
        .col(large_blob_null(TrustEntity::Content, manager))
        .col(string(TrustEntity::Type))
        .col(string(TrustEntity::Role))
        .col(string(TrustEntity::State))
        .col(string_len(TrustEntity::EntityKey, 4000))
        .col(text_null(TrustEntity::Website))
        .col(text_null(TrustEntity::TermsUrl))
        .col(text_null(TrustEntity::PrivacyUrl))
        .col(uuid_char_null(TrustEntity::OrganisationId))
        .col(uuid_char(TrustEntity::TrustAnchorId))
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_TRUST_ENTITY_TRUST_ANCHOR)
                .from_tbl(TrustEntity::Table)
                .from_col(TrustEntity::TrustAnchorId)
                .to_tbl(TrustAnchor::Table)
                .to_col(TrustAnchor::Id),
        )
        .foreign_key(
            ForeignKeyCreateStatement::new()
                .name(FK_TRUST_ENTITY_ORGANISATION)
                .from_tbl(TrustEntity::Table)
                .from_col(TrustEntity::OrganisationId)
                .to_tbl(Organisation::Table)
                .to_col(Organisation::Id),
        )
        .to_owned();
    table_with_indexes(table, vec![], manager).await?;
    add_nullable_unique_idx(
        TrustEntity::Table,
        TrustEntity::DeactivatedAt,
        INDEX_UNIQUE_TRUST_ENTITY_NAME_ORGANISATION_DEACTIVATED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![TrustEntity::Name, TrustEntity::OrganisationId],
            null_value: Some("not_deactivated"),
            ..Default::default()
        },
        manager,
    )
    .await?;
    add_nullable_unique_idx(
        TrustEntity::Table,
        TrustEntity::DeactivatedAt,
        INDEX_UNIQUE_TRUST_ENTITY_ENTITY_KEY_ANCHOR_DEACTIVATED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![TrustEntity::EntityKey, TrustEntity::TrustAnchorId],
            null_value: Some("not_deactivated"),
            ..Default::default()
        },
        manager,
    )
    .await
}

#[derive(DeriveIden)]
pub enum BlobStorage {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Type,
    Value,
}

#[derive(DeriveIden, Clone)]
pub enum Certificate {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeletedAt,
    ExpiryDate,
    IdentifierId,
    Name,
    Chain,
    State,
    KeyId,
    Fingerprint,
    OrganisationId,
    Roles,
}

#[derive(DeriveIden)]
pub enum Claim {
    Table,
    Id,
    ClaimSchemaId,
    CredentialId,
    Value,
    CreatedDate,
    LastModified,
    Path,
    SelectivelyDisclosable,
}

#[derive(DeriveIden)]
pub enum ClaimSchema {
    Table,
    Id,
    Key,
    Datatype,
    CreatedDate,
    LastModified,
    Array,
    Metadata,
    CredentialSchemaId,
    Required,
    Order,
}

#[derive(DeriveIden)]
pub enum Credential {
    Table,
    Id,
    CreatedDate,
    LastModified,
    IssuanceDate,
    DeletedAt,
    Protocol,
    CredentialSchemaId,
    InteractionId,
    KeyId,
    Role,
    RedirectUri,
    State,
    SuspendEndDate,
    HolderIdentifierId,
    IssuerIdentifierId,
    IssuerCertificateId,
    Profile,
    CredentialBlobId,
    WalletUnitAttestationBlobId,
    WalletInstanceAttestationBlobId,
    WebhookUrl,
}

#[derive(DeriveIden)]
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
    SchemaId,
    LayoutType,
    LayoutProperties,
    ImportedSourceUrl,
    AllowSuspension,
    RequiresWalletInstanceAttestation,
    KeyStorageSecurity,
    TransactionCodeType,
    TransactionCodeLength,
    TransactionCodeDescription,
}

#[derive(DeriveIden, Clone)]
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
    DeletedAt,
    Log,
}

#[derive(DeriveIden)]
pub enum History {
    Table,
    Id,
    CreatedDate,
    Action,
    EntityId,
    EntityType,
    OrganisationId,
    Metadata,
    Name,
    Target,
    User,
    Source,
    MetadataBlobId,
}

#[derive(DeriveIden)]
pub enum HolderWalletInstance {
    Table,
    Id,
    OrganisationId,
    AuthenticationKeyId,
    CreatedDate,
    LastModified,
    WalletProviderName,
    WalletProviderType,
    WalletProviderUrl,
    ProviderWalletUnitId,
    Status,
}

#[derive(Clone, DeriveIden)]
pub enum Identifier {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Name,
    Type,
    IsRemote,
    State,
    OrganisationId,
    DidId,
    KeyId,
    DeletedAt,
}

#[derive(DeriveIden)]
pub enum IdentifierTrustInformation {
    Table,
    Id,
    CreatedDate,
    LastModified,
    ValidFrom,
    ValidTo,
    IntendedUse,
    AllowedIssuanceTypes,
    AllowedVerificationTypes,
    BlobId,
    IdentifierId,
}

#[derive(DeriveIden)]
pub enum Interaction {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Data,
    OrganisationId,
    NonceId,
    InteractionType,
    ExpiresAt,
}

#[derive(DeriveIden)]
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
    DeletedAt,
}

#[derive(DeriveIden)]
pub enum KeyDid {
    Table,
    DidId,
    KeyId,
    Role,
    Reference,
}

#[derive(DeriveIden)]
pub enum Notification {
    Table,
    Id,
    Url,
    Payload,
    CreatedDate,
    NextTryDate,
    TriesCount,
    Type,
    HistoryTarget,
    OrganisationId,
}

#[derive(Clone, DeriveIden)]
pub enum Organisation {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeactivatedAt,
    WalletProvider,
    WalletProviderIssuer,
    ParentOrganisation,
}

#[derive(DeriveIden)]
pub enum Proof {
    Table,
    Id,
    CreatedDate,
    LastModified,
    RedirectUri,
    ProofSchemaId,
    Transport,
    InteractionId,
    VerifierKeyId,
    Protocol,
    State,
    RequestedDate,
    CompletedDate,
    Role,
    VerifierIdentifierId,
    VerifierCertificateId,
    Profile,
    ProofBlobId,
    Engagement,
    WebhookUrl,
}

#[derive(DeriveIden)]
pub enum ProofClaim {
    Table,
    ClaimId,
    ProofId,
}

#[derive(DeriveIden)]
pub enum ProofInputClaimSchema {
    Table,
    ClaimSchemaId,
    ProofInputSchemaId,
    Order,
    Required,
}

#[derive(DeriveIden)]
pub enum ProofInputSchema {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Order,
    CredentialSchema,
    ProofSchema,
}

#[derive(DeriveIden)]
pub enum ProofSchema {
    Table,
    Id,
    DeletedAt,
    CreatedDate,
    LastModified,
    Name,
    ExpireDuration,
    OrganisationId,
    ImportedSourceUrl,
}

#[derive(DeriveIden)]
pub enum RemoteEntityCache {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Key,
    MediaType,
    ExpirationDate,
    LastUsed,
    Type,
    Value,
}

#[derive(DeriveIden)]
pub enum RevocationList {
    Table,
    Id,
    CreatedDate,
    LastModified,
    FormattedList,
    Purpose,
    Format,
    Type,
    IssuerIdentifierId,
    IssuerCertificateId,
}

#[derive(DeriveIden)]
pub enum RevocationListEntry {
    Table,
    Id,
    CreatedDate,
    RevocationListId,
    Index,
    CredentialId,
    State,
    Type,
    SignatureType,
    Serial,
    LastModified,
}

#[derive(DeriveIden)]
pub enum TrustAnchor {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Name,
    Type,
    IsPublisher,
    PublisherReference,
}

#[derive(DeriveIden)]
pub enum TrustCollection {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeactivatedAt,
    Name,
    OrganisationId,
    RemoteTrustCollectionUrl,
}

#[derive(DeriveIden)]
pub enum TrustEntity {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Name,
    Logo,
    Website,
    TermsUrl,
    PrivacyUrl,
    Role,
    State,
    TrustAnchorId,
    OrganisationId,
    Type,
    EntityKey,
    Content,
    DeactivatedAt,
}

#[derive(DeriveIden)]
pub enum TrustEntry {
    Table,
    Id,
    CreatedDate,
    LastModified,
    State,
    Metadata,
    TrustListPublicationId,
    IdentifierId,
}

#[derive(DeriveIden)]
pub enum TrustListPublication {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Name,
    Role,
    Type,
    Metadata,
    DeactivatedAt,
    Content,
    SequenceNumber,
    OrganisationId,
    IdentifierId,
    KeyId,
    CertificateId,
}

#[derive(DeriveIden)]
pub enum TrustListSubscription {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeactivatedAt,
    Name,
    Role,
    Type,
    State,
    Reference,
    TrustCollectionId,
}

#[derive(DeriveIden)]
pub enum ValidityCredential {
    Table,
    Id,
    CreatedDate,
    Credential,
    CredentialId,
    Type,
}

#[derive(DeriveIden)]
pub enum VerifierInstance {
    Table,
    Id,
    CreatedDate,
    LastModified,
    ProviderUrl,
    ProviderName,
    ProviderType,
    OrganisationId,
}

#[derive(DeriveIden)]
pub enum WalletInstance {
    Table,
    Id,
    OrganisationId,
    CreatedDate,
    LastModified,
    LastIssuance,
    Name,
    Os,
    Status,
    Nonce,
    WalletProviderType,
    WalletProviderName,
    AuthenticationKeyJwk,
}

#[derive(DeriveIden)]
pub enum WalletInstanceAttestation {
    Table,
    Id,
    CreatedDate,
    LastModified,
    ExpirationDate,
    Attestation,
    HolderWalletUnitId,
    AttestedKeyId,
    RevocationListUrl,
    RevocationListIndex,
}

#[derive(DeriveIden)]
pub enum WalletInstanceAttestedKey {
    Table,
    Id,
    CreatedDate,
    LastModified,
    ExpirationDate,
    PublicKeyJwk,
    WalletInstanceId,
    RevocationListEntryId,
}
