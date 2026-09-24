use std::collections::HashMap;

use sea_orm::FromQueryResult;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{
    integer_null, json_binary_null, string, string_null, text, text_null,
};
use serde::Serialize;
use serde_with::skip_serializing_none;
use time::OffsetDateTime;

use crate::datatype::{large_blob, timestamp, timestamp_null, uuid_char, uuid_char_null};
use crate::migrations::m20260417_150300_initial::{
    HolderWalletInstance, Identifier, Key, Organisation, RevocationListEntry, VerifierInstance,
    WalletInstance, WalletInstanceAttestation, WalletInstanceAttestedKey,
};
use crate::migrations::m20260427_113000_add_trusted_requirements::VerifierInstance as VerifierInstanceWithTrustedIssuerRequired;
use crate::migrations::m20260429_083200_move_trusted_rp_required_to_holder_wallet_instance::HolderWalletInstance as HolderWalletInstanceWithTrustedRpRequired;
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        managed_instance_table(manager).await?;
        managed_instance_attested_key_table(manager).await?;
        manager
            .drop_table(
                Table::drop()
                    .table(WalletInstanceAttestedKey::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(WalletInstance::Table).to_owned())
            .await?;

        instance_table(manager).await?;
        wallet_instance_attestation_table(manager).await?;
        if manager.supported_db_type() == SupportedDbType::Sqlite {
            organisation_table_schema_sqlite(manager).await?;
        } else {
            organisation_table_schema_simple(manager).await?;
        }
        fill_organisations(manager).await?;

        manager
            .drop_table(Table::drop().table(VerifierInstance::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(HolderWalletInstance::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub(crate) enum ManagedInstance {
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
    Provider,
    AuthenticationKeyJwk,
    UserNonce,
    UserSub,
    Role,
    VerifierCsr,
    VerifierSignatureIds,
}

async fn managed_instance_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(ManagedInstance::Table)
                .col(uuid_char(ManagedInstance::Id).primary_key())
                .col(timestamp(ManagedInstance::CreatedDate, manager))
                .col(timestamp(ManagedInstance::LastModified, manager))
                .col(timestamp_null(ManagedInstance::LastIssuance, manager))
                .col(string(ManagedInstance::Name))
                .col(string(ManagedInstance::Os))
                .col(string(ManagedInstance::Status))
                .col(string_null(ManagedInstance::Nonce))
                .col(string(ManagedInstance::Provider))
                .col(text_null(ManagedInstance::AuthenticationKeyJwk))
                .col(uuid_char(ManagedInstance::OrganisationId))
                .col(string_null(ManagedInstance::UserNonce))
                .col(string_null(ManagedInstance::UserSub))
                .col(string(ManagedInstance::Role))
                .col(text_null(ManagedInstance::VerifierCsr))
                .col(json_binary_null(ManagedInstance::VerifierSignatureIds))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-ManagedInstance-OrganisationId")
                        .from_tbl(ManagedInstance::Table)
                        .from_col(ManagedInstance::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-ManagedInstance-AuthenticationKey-Organisation-Role-Unique")
                .unique()
                .table(ManagedInstance::Table)
                .col(ManagedInstance::AuthenticationKeyJwk)
                .col(ManagedInstance::OrganisationId)
                .col(ManagedInstance::Role)
                .to_owned(),
        )
        .await?;

    #[derive(FromQueryResult)]
    struct OldEntry {
        id: String,
        organisation_id: String,
        created_date: OffsetDateTime,
        last_modified: OffsetDateTime,
        last_issuance: Option<OffsetDateTime>,
        name: String,
        os: String,
        status: String,
        nonce: Option<String>,
        wallet_provider_name: String,
        authentication_key_jwk: Option<String>,
        user_nonce: Option<String>,
        user_sub: Option<String>,
    }

    let db = manager.get_connection();
    let backend = db.get_database_backend();
    let old_entries = OldEntry::find_by_statement(
        backend.build(
            Query::select()
                .columns([
                    WalletInstance::Id,
                    WalletInstance::OrganisationId,
                    WalletInstance::CreatedDate,
                    WalletInstance::LastModified,
                    WalletInstance::LastIssuance,
                    WalletInstance::Name,
                    WalletInstance::Os,
                    WalletInstance::Status,
                    WalletInstance::Nonce,
                    WalletInstance::WalletProviderName,
                    WalletInstance::AuthenticationKeyJwk,
                ])
                .column(ManagedInstance::UserNonce)
                .column(ManagedInstance::UserSub)
                .from(WalletInstance::Table),
        ),
    )
    .all(db)
    .await?;

    for entry in old_entries {
        db.execute(
            Query::insert()
                .into_table(ManagedInstance::Table)
                .columns([
                    ManagedInstance::Id,
                    ManagedInstance::OrganisationId,
                    ManagedInstance::CreatedDate,
                    ManagedInstance::LastModified,
                    ManagedInstance::LastIssuance,
                    ManagedInstance::Name,
                    ManagedInstance::Os,
                    ManagedInstance::Status,
                    ManagedInstance::Nonce,
                    ManagedInstance::Provider,
                    ManagedInstance::AuthenticationKeyJwk,
                    ManagedInstance::UserNonce,
                    ManagedInstance::UserSub,
                    ManagedInstance::Role,
                ])
                .values([
                    entry.id.into(),
                    entry.organisation_id.into(),
                    entry.created_date.into(),
                    entry.last_modified.into(),
                    entry.last_issuance.into(),
                    entry.name.into(),
                    entry.os.into(),
                    entry.status.into(),
                    entry.nonce.into(),
                    entry.wallet_provider_name.into(),
                    entry.authentication_key_jwk.into(),
                    entry.user_nonce.into(),
                    entry.user_sub.into(),
                    "WALLET".into(),
                ])
                .map_err(|e| DbErr::Migration(e.to_string()))?,
        )
        .await?;
    }

    Ok(())
}

#[derive(DeriveIden)]
pub(crate) enum ManagedInstanceAttestedKey {
    Table,
    Id,
    CreatedDate,
    LastModified,
    ExpirationDate,
    PublicKeyJwk,
    ManagedInstanceId,
    RevocationListEntryId,
}

async fn managed_instance_attested_key_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(ManagedInstanceAttestedKey::Table)
                .col(uuid_char(ManagedInstanceAttestedKey::Id).primary_key())
                .col(timestamp(ManagedInstanceAttestedKey::CreatedDate, manager))
                .col(timestamp(ManagedInstanceAttestedKey::LastModified, manager))
                .col(timestamp(
                    ManagedInstanceAttestedKey::ExpirationDate,
                    manager,
                ))
                .col(text(ManagedInstanceAttestedKey::PublicKeyJwk))
                .col(uuid_char(ManagedInstanceAttestedKey::ManagedInstanceId))
                .col(uuid_char_null(
                    ManagedInstanceAttestedKey::RevocationListEntryId,
                ))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-ManagedInstanceAttestedKey-ManagedInstanceId")
                        .from_tbl(ManagedInstanceAttestedKey::Table)
                        .from_col(ManagedInstanceAttestedKey::ManagedInstanceId)
                        .to_tbl(ManagedInstance::Table)
                        .to_col(ManagedInstance::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-ManagedInstanceAttestedKey-RevocationListEntryId")
                        .from_tbl(ManagedInstanceAttestedKey::Table)
                        .from_col(ManagedInstanceAttestedKey::RevocationListEntryId)
                        .to_tbl(RevocationListEntry::Table)
                        .to_col(RevocationListEntry::Id),
                )
                .to_owned(),
        )
        .await?;

    #[derive(FromQueryResult)]
    struct OldEntry {
        id: String,
        created_date: OffsetDateTime,
        last_modified: OffsetDateTime,
        expiration_date: OffsetDateTime,
        public_key_jwk: String,
        wallet_instance_id: String,
        revocation_list_entry_id: Option<String>,
    }

    let db = manager.get_connection();
    let backend = db.get_database_backend();
    let old_entries = OldEntry::find_by_statement(
        backend.build(
            Query::select()
                .columns([
                    WalletInstanceAttestedKey::Id,
                    WalletInstanceAttestedKey::CreatedDate,
                    WalletInstanceAttestedKey::LastModified,
                    WalletInstanceAttestedKey::ExpirationDate,
                    WalletInstanceAttestedKey::PublicKeyJwk,
                    WalletInstanceAttestedKey::WalletInstanceId,
                    WalletInstanceAttestedKey::RevocationListEntryId,
                ])
                .from(WalletInstanceAttestedKey::Table),
        ),
    )
    .all(db)
    .await?;

    for entry in old_entries {
        db.execute(
            Query::insert()
                .into_table(ManagedInstanceAttestedKey::Table)
                .columns([
                    ManagedInstanceAttestedKey::Id,
                    ManagedInstanceAttestedKey::CreatedDate,
                    ManagedInstanceAttestedKey::LastModified,
                    ManagedInstanceAttestedKey::ExpirationDate,
                    ManagedInstanceAttestedKey::PublicKeyJwk,
                    ManagedInstanceAttestedKey::ManagedInstanceId,
                    ManagedInstanceAttestedKey::RevocationListEntryId,
                ])
                .values([
                    entry.id.into(),
                    entry.created_date.into(),
                    entry.last_modified.into(),
                    entry.expiration_date.into(),
                    entry.public_key_jwk.into(),
                    entry.wallet_instance_id.into(),
                    entry.revocation_list_entry_id.into(),
                ])
                .map_err(|e| DbErr::Migration(e.to_string()))?,
        )
        .await?;
    }

    Ok(())
}

#[derive(DeriveIden)]
pub(crate) enum Instance {
    Table,
    Id,
    AuthenticationKeyId,
    CreatedDate,
    LastModified,
    ProviderName,
    ProviderType,
    ProviderUrl,
    ProviderInstanceId,
    Status,
    Nonce,
    UserNonce,
    OrganisationId,
    Role,
}

async fn instance_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(Instance::Table)
                .col(uuid_char(Instance::Id).primary_key())
                .col(uuid_char_null(Instance::AuthenticationKeyId))
                .col(timestamp(Instance::CreatedDate, manager))
                .col(timestamp(Instance::LastModified, manager))
                .col(string(Instance::ProviderName))
                .col(string(Instance::ProviderType))
                .col(string(Instance::ProviderUrl))
                .col(uuid_char(Instance::ProviderInstanceId))
                .col(string(Instance::Status))
                .col(string_null(Instance::Nonce))
                .col(string_null(Instance::UserNonce))
                .col(uuid_char(Instance::OrganisationId))
                .col(string(Instance::Role))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-Instance-AuthenticationKeyId")
                        .from_tbl(Instance::Table)
                        .from_col(Instance::AuthenticationKeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-Instance-OrganisationId")
                        .from_tbl(Instance::Table)
                        .from_col(Instance::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Instance-Role-OrganisationId-Unique")
                .unique()
                .table(Instance::Table)
                .col(Instance::Role)
                .col(Instance::OrganisationId)
                .to_owned(),
        )
        .await?;

    #[derive(FromQueryResult)]
    struct OldEntry {
        id: String,
        created_date: OffsetDateTime,
        last_modified: OffsetDateTime,
        status: String,
        wallet_provider_name: String,
        wallet_provider_type: String,
        wallet_provider_url: String,
        provider_wallet_unit_id: String,
        authentication_key_id: Option<String>,
        organisation_id: String,
        nonce: Option<String>,
        user_nonce: Option<String>,
    }

    let db = manager.get_connection();
    let backend = db.get_database_backend();
    let old_entries = OldEntry::find_by_statement(
        backend.build(
            Query::select()
                .columns([
                    HolderWalletInstance::Id,
                    HolderWalletInstance::AuthenticationKeyId,
                    HolderWalletInstance::CreatedDate,
                    HolderWalletInstance::LastModified,
                    HolderWalletInstance::WalletProviderName,
                    HolderWalletInstance::WalletProviderType,
                    HolderWalletInstance::WalletProviderUrl,
                    HolderWalletInstance::ProviderWalletUnitId,
                    HolderWalletInstance::Status,
                    HolderWalletInstance::OrganisationId,
                ])
                .column(Instance::Nonce)
                .column(Instance::UserNonce)
                .from(HolderWalletInstance::Table),
        ),
    )
    .all(db)
    .await?;

    for entry in old_entries {
        db.execute(
            Query::insert()
                .into_table(Instance::Table)
                .columns([
                    Instance::Id,
                    Instance::AuthenticationKeyId,
                    Instance::CreatedDate,
                    Instance::LastModified,
                    Instance::ProviderName,
                    Instance::ProviderType,
                    Instance::ProviderUrl,
                    Instance::ProviderInstanceId,
                    Instance::Status,
                    Instance::OrganisationId,
                    Instance::Nonce,
                    Instance::UserNonce,
                    Instance::Role,
                ])
                .values([
                    entry.id.into(),
                    entry.authentication_key_id.into(),
                    entry.created_date.into(),
                    entry.last_modified.into(),
                    entry.wallet_provider_name.into(),
                    entry.wallet_provider_type.into(),
                    entry.wallet_provider_url.into(),
                    entry.provider_wallet_unit_id.into(),
                    entry.status.into(),
                    entry.organisation_id.into(),
                    entry.nonce.into(),
                    entry.user_nonce.into(),
                    "WALLET".into(),
                ])
                .map_err(|e| DbErr::Migration(e.to_string()))?,
        )
        .await?;
    }

    Ok(())
}

#[derive(DeriveIden)]
pub(crate) enum NewWalletInstanceAttestation {
    Table,
    Id,
    CreatedDate,
    LastModified,
    ExpirationDate,
    Attestation,
    InstanceId,
    AttestedKeyId,
    RevocationListUrl,
    RevocationListIndex,
}

async fn wallet_instance_attestation_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(NewWalletInstanceAttestation::Table)
                .col(uuid_char(NewWalletInstanceAttestation::Id).primary_key())
                .col(timestamp(
                    NewWalletInstanceAttestation::CreatedDate,
                    manager,
                ))
                .col(timestamp(
                    NewWalletInstanceAttestation::LastModified,
                    manager,
                ))
                .col(timestamp(
                    NewWalletInstanceAttestation::ExpirationDate,
                    manager,
                ))
                .col(string_null(NewWalletInstanceAttestation::RevocationListUrl))
                .col(integer_null(
                    NewWalletInstanceAttestation::RevocationListIndex,
                ))
                .col(large_blob(
                    NewWalletInstanceAttestation::Attestation,
                    manager,
                ))
                .col(uuid_char(NewWalletInstanceAttestation::InstanceId))
                .col(uuid_char(NewWalletInstanceAttestation::AttestedKeyId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-WalletInstanceAttestation-InstanceId")
                        .from_tbl(NewWalletInstanceAttestation::Table)
                        .from_col(NewWalletInstanceAttestation::InstanceId)
                        .to_tbl(Instance::Table)
                        .to_col(Instance::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-WalletInstanceAttestation-AttestedKeyId")
                        .from_tbl(NewWalletInstanceAttestation::Table)
                        .from_col(NewWalletInstanceAttestation::AttestedKeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .to_owned(),
        )
        .await?;

    #[derive(FromQueryResult)]
    struct OldEntry {
        id: String,
        created_date: OffsetDateTime,
        last_modified: OffsetDateTime,
        expiration_date: OffsetDateTime,
        attestation: Vec<u8>,
        revocation_list_url: Option<String>,
        revocation_list_index: Option<i64>,
        holder_wallet_unit_id: String,
        attested_key_id: String,
    }

    let db = manager.get_connection();
    let backend = db.get_database_backend();
    let old_entries = OldEntry::find_by_statement(
        backend.build(
            Query::select()
                .columns([
                    WalletInstanceAttestation::Id,
                    WalletInstanceAttestation::CreatedDate,
                    WalletInstanceAttestation::LastModified,
                    WalletInstanceAttestation::ExpirationDate,
                    WalletInstanceAttestation::Attestation,
                    WalletInstanceAttestation::HolderWalletUnitId,
                    WalletInstanceAttestation::AttestedKeyId,
                    WalletInstanceAttestation::RevocationListUrl,
                    WalletInstanceAttestation::RevocationListIndex,
                ])
                .from(WalletInstanceAttestation::Table),
        ),
    )
    .all(db)
    .await?;

    for entry in old_entries {
        db.execute(
            Query::insert()
                .into_table(NewWalletInstanceAttestation::Table)
                .columns([
                    NewWalletInstanceAttestation::Id,
                    NewWalletInstanceAttestation::CreatedDate,
                    NewWalletInstanceAttestation::LastModified,
                    NewWalletInstanceAttestation::ExpirationDate,
                    NewWalletInstanceAttestation::Attestation,
                    NewWalletInstanceAttestation::InstanceId,
                    NewWalletInstanceAttestation::AttestedKeyId,
                    NewWalletInstanceAttestation::RevocationListUrl,
                    NewWalletInstanceAttestation::RevocationListIndex,
                ])
                .values([
                    entry.id.into(),
                    entry.created_date.into(),
                    entry.last_modified.into(),
                    entry.expiration_date.into(),
                    entry.attestation.into(),
                    entry.holder_wallet_unit_id.into(),
                    entry.attested_key_id.into(),
                    entry.revocation_list_url.into(),
                    entry.revocation_list_index.into(),
                ])
                .map_err(|e| DbErr::Migration(e.to_string()))?,
        )
        .await?;
    }

    manager
        .drop_table(
            Table::drop()
                .table(WalletInstanceAttestation::Table)
                .to_owned(),
        )
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(
                    NewWalletInstanceAttestation::Table,
                    WalletInstanceAttestation::Table,
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-WalletInstanceAttestation-AttestedKey-Unique")
                .unique()
                .table(WalletInstanceAttestation::Table)
                .col(WalletInstanceAttestation::AttestedKeyId)
                .to_owned(),
        )
        .await?;

    Ok(())
}

#[derive(DeriveIden)]
enum NewOrganisation {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeactivatedAt,
    WalletProvider,
    WalletProviderIssuer,
    ParentOrganisation,

    // newly added
    Configuration,
    VerifierProvider,
    VerifierProviderIssuer,
}

async fn organisation_table_schema_simple(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Organisation::Table)
                .add_column(json_binary_null(NewOrganisation::Configuration))
                .add_column(string_null(NewOrganisation::VerifierProvider))
                .add_column(uuid_char_null(NewOrganisation::VerifierProviderIssuer))
                .add_foreign_key(
                    TableForeignKey::new()
                        .name("fk-Organisation-VerifierProviderIssuer")
                        .from_tbl(Organisation::Table)
                        .from_col(NewOrganisation::VerifierProviderIssuer)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Organisation-VerifierProvider-Unique")
                .unique()
                .table(Organisation::Table)
                .col(NewOrganisation::VerifierProvider)
                .to_owned(),
        )
        .await?;

    Ok(())
}

async fn organisation_table_schema_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    manager
        .create_table(
            Table::create()
                .table(NewOrganisation::Table)
                .col(uuid_char(NewOrganisation::Id).primary_key())
                .col(timestamp(NewOrganisation::CreatedDate, manager))
                .col(timestamp(NewOrganisation::LastModified, manager))
                .col(timestamp_null(NewOrganisation::DeactivatedAt, manager))
                .col(string_null(NewOrganisation::WalletProvider))
                .col(uuid_char_null(NewOrganisation::ParentOrganisation))
                .col(uuid_char_null(NewOrganisation::WalletProviderIssuer))
                .col(json_binary_null(NewOrganisation::Configuration))
                .col(string_null(NewOrganisation::VerifierProvider))
                .col(uuid_char_null(NewOrganisation::VerifierProviderIssuer))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-Organisation-ParentOrganisation")
                        .from_tbl(NewOrganisation::Table)
                        .from_col(NewOrganisation::ParentOrganisation)
                        .to_tbl(NewOrganisation::Table)
                        .to_col(NewOrganisation::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-OrganisationWalletUnitIssuer-IssuerId")
                        .from_tbl(NewOrganisation::Table)
                        .from_col(NewOrganisation::WalletProviderIssuer)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-Organisation-VerifierProviderIssuer")
                        .from_tbl(NewOrganisation::Table)
                        .from_col(NewOrganisation::VerifierProviderIssuer)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        Organisation::Id,
        Organisation::CreatedDate,
        Organisation::LastModified,
        Organisation::DeactivatedAt,
        Organisation::WalletProvider,
        Organisation::WalletProviderIssuer,
        Organisation::ParentOrganisation,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(NewOrganisation::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(Organisation::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(Organisation::Table).to_owned())
        .await?;
    manager
        .rename_table(
            Table::rename()
                .table(NewOrganisation::Table, Organisation::Table)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Organisation-WalletProvider-Unique")
                .unique()
                .table(Organisation::Table)
                .col(Organisation::WalletProvider)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Organisation-VerifierProvider-Unique")
                .unique()
                .table(Organisation::Table)
                .col(NewOrganisation::VerifierProvider)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Organisation-ParentOrganisation")
                .table(Organisation::Table)
                .col(Organisation::ParentOrganisation)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

async fn fill_organisations(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    let backend = db.get_database_backend();

    #[derive(FromQueryResult)]
    struct WalletEntry {
        organisation_id: String,
        trusted_rp_required: bool,
    }

    let wallet_entries = WalletEntry::find_by_statement(
        backend.build(
            Query::select()
                .column(HolderWalletInstance::OrganisationId)
                .column(HolderWalletInstanceWithTrustedRpRequired::TrustedRpRequired)
                .from(HolderWalletInstance::Table),
        ),
    )
    .all(db)
    .await?;

    #[derive(FromQueryResult)]
    struct VerifierEntry {
        organisation_id: String,
        trusted_issuer_required: bool,
    }

    let verifier_entries = VerifierEntry::find_by_statement(
        backend.build(
            Query::select()
                .column(VerifierInstance::OrganisationId)
                .column(VerifierInstanceWithTrustedIssuerRequired::TrustedIssuerRequired)
                .from(VerifierInstance::Table),
        ),
    )
    .all(db)
    .await?;

    #[skip_serializing_none]
    #[derive(Serialize, Default)]
    struct OrganisationConfiguration {
        trusted_rp_required: Option<bool>,
        trusted_issuer_required: Option<bool>,
    }

    let mut configurations: HashMap<String, OrganisationConfiguration> = HashMap::new();
    for wallet_entry in wallet_entries {
        configurations
            .entry(wallet_entry.organisation_id)
            .or_default()
            .trusted_rp_required = Some(wallet_entry.trusted_rp_required);
    }
    for verifier_entry in verifier_entries {
        configurations
            .entry(verifier_entry.organisation_id)
            .or_default()
            .trusted_issuer_required = Some(verifier_entry.trusted_issuer_required);
    }

    for (organisation_id, configuration) in configurations {
        manager
            .exec_stmt(
                Query::update()
                    .table(Organisation::Table)
                    .value(
                        NewOrganisation::Configuration,
                        serde_json::to_value(&configuration)
                            .map_err(|e| DbErr::Migration(e.to_string()))?,
                    )
                    .cond_where(Expr::col(Organisation::Id).eq(organisation_id))
                    .to_owned(),
            )
            .await?;
    }

    Ok(())
}
