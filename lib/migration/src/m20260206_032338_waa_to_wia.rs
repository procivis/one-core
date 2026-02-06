use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, string, string_len_null, string_null, unsigned_null};

use crate::datatype::{timestamp, timestamp_null, uuid_char, uuid_char_null};
use crate::m20240110_000001_initial::{Interaction, Key, Organisation};
use crate::m20250429_142011_add_identifier::Identifier;
use crate::m20250512_110852_certificate::Certificate;
use crate::m20251105_121212_waa_and_wua_blobs::BlobStorage;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres => {
                return Ok(());
            }
            DatabaseBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(CredentialSchema::Table)
                            .rename_column(
                                CredentialSchema::RequiresAppAttestation,
                                CredentialSchema::RequiresWalletInstanceAttestation,
                            )
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(Credential::Table)
                            .drop_foreign_key(Alias::new(
                                "fk_credential_wallet_app_attestation_blob_id",
                            ))
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(Credential::Table)
                            .rename_column(
                                Credential::WalletAppAttestationBlobId,
                                Credential::WalletInstanceAttestationBlobId,
                            )
                            .add_foreign_key(
                                ForeignKey::create()
                                    .name("fk_credential_wallet_instance_attestation_blob_id")
                                    .from_tbl(Credential::Table)
                                    .from_col(Credential::WalletInstanceAttestationBlobId)
                                    .to_tbl(BlobStorage::Table)
                                    .to_col(BlobStorage::Id)
                                    .on_delete(ForeignKeyAction::SetNull)
                                    .get_foreign_key(),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            DatabaseBackend::Sqlite => sqlite_migration(manager).await?,
        };

        manager
            .exec_stmt(
                Query::update()
                    .table(BlobStorage::Table)
                    .value(BlobStorage::Type, "WALLET_INSTANCE_ATTESTATION".to_string())
                    .and_where(Expr::col(BlobStorage::Type).eq(Expr::val("WALLET_APP_ATTESTATION")))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
enum CredentialSchemaNew {
    Table,
}

#[derive(Clone, Iden)]
enum CredentialSchema {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeletedAt,
    Name,
    Format,
    RevocationMethod,
    OrganisationId,
    SchemaId,
    LayoutProperties,
    LayoutType,
    ImportedSourceUrl,
    AllowSuspension,
    KeyStorageSecurity,
    TransactionCodeType,
    TransactionCodeLength,
    TransactionCodeDescription,

    RequiresAppAttestation,
    RequiresWalletInstanceAttestation,
}

#[derive(DeriveIden)]
enum CredentialNew {
    Table,
}

#[expect(clippy::enum_variant_names)]
#[derive(Clone, DeriveIden)]
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

    WalletAppAttestationBlobId,
    WalletInstanceAttestationBlobId,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // credential_schema table
    manager
        .create_table(
            Table::create()
                .table(CredentialSchemaNew::Table)
                .col(uuid_char(CredentialSchema::Id).primary_key())
                .col(timestamp(CredentialSchema::CreatedDate, manager))
                .col(timestamp(CredentialSchema::LastModified, manager))
                .col(timestamp_null(CredentialSchema::DeletedAt, manager))
                .col(string(CredentialSchema::Name))
                .col(string(CredentialSchema::Format))
                .col(string_null(CredentialSchema::RevocationMethod))
                .col(uuid_char(CredentialSchema::OrganisationId))
                .col(string(CredentialSchema::SchemaId))
                .col(
                    ColumnDef::new(CredentialSchema::LayoutProperties)
                        .json()
                        .null(),
                )
                .col(string(CredentialSchema::LayoutType))
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
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-CredentialSchema-OrganisationId")
                        .from_tbl(CredentialSchemaNew::Table)
                        .from_col(CredentialSchema::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    let shared_copied_columns = vec![
        CredentialSchema::Id,
        CredentialSchema::CreatedDate,
        CredentialSchema::LastModified,
        CredentialSchema::DeletedAt,
        CredentialSchema::Name,
        CredentialSchema::Format,
        CredentialSchema::RevocationMethod,
        CredentialSchema::OrganisationId,
        CredentialSchema::SchemaId,
        CredentialSchema::LayoutProperties,
        CredentialSchema::LayoutType,
        CredentialSchema::ImportedSourceUrl,
        CredentialSchema::AllowSuspension,
        CredentialSchema::KeyStorageSecurity,
        CredentialSchema::TransactionCodeType,
        CredentialSchema::TransactionCodeLength,
        CredentialSchema::TransactionCodeDescription,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(CredentialSchemaNew::Table)
                .columns(
                    [
                        [CredentialSchema::RequiresWalletInstanceAttestation].as_slice(),
                        shared_copied_columns.as_slice(),
                    ]
                    .concat(),
                )
                .select_from(
                    Query::select()
                        .from(CredentialSchema::Table)
                        .columns(
                            [
                                [CredentialSchema::RequiresAppAttestation].as_slice(),
                                shared_copied_columns.as_slice(),
                            ]
                            .concat(),
                        )
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(CredentialSchema::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(CredentialSchemaNew::Table, CredentialSchema::Table)
                .to_owned(),
        )
        .await?;

    manager
        .get_connection()
        .execute_unprepared(
            r#"
            CREATE UNIQUE INDEX `index-Organisation-SchemaId-DeletedAt_Unique`
            ON credential_schema(
                `organisation_id`,
                `schema_id`,
                COALESCE(deleted_at, 'not_deleted')
            );
            "#,
        )
        .await?;

    manager
        .get_connection()
        .execute_unprepared(
            r#"
            CREATE UNIQUE INDEX `index_CredentialSchema_Name-OrganisationId-DeletedAt_Unique`
            ON credential_schema(
                `name`,
                `organisation_id`,
                COALESCE(deleted_at, 'not_deleted')
            );
            "#,
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-CredentialSchema-CreatedDate")
                .table(CredentialSchema::Table)
                .col(CredentialSchema::CreatedDate)
                .to_owned(),
        )
        .await?;

    // credential table
    manager
        .create_table(
            Table::create()
                .table(CredentialNew::Table)
                .col(uuid_char(Credential::Id).primary_key())
                .col(timestamp(Credential::CreatedDate, manager))
                .col(timestamp(Credential::LastModified, manager))
                .col(timestamp_null(Credential::IssuanceDate, manager))
                .col(timestamp_null(Credential::DeletedAt, manager))
                .col(string(Credential::Protocol))
                .col(uuid_char(Credential::CredentialSchemaId))
                .col(uuid_char_null(Credential::InteractionId))
                .col(uuid_char_null(Credential::KeyId))
                .col(string(Credential::Role))
                .col(string_len_null(Credential::RedirectUri, 1000))
                .col(string(Credential::State))
                .col(timestamp_null(Credential::SuspendEndDate, manager))
                .col(uuid_char_null(Credential::HolderIdentifierId))
                .col(uuid_char_null(Credential::IssuerIdentifierId))
                .col(uuid_char_null(Credential::IssuerCertificateId))
                .col(string_null(Credential::Profile))
                .col(uuid_char_null(Credential::CredentialBlobId))
                .col(uuid_char_null(Credential::WalletUnitAttestationBlobId))
                .col(uuid_char_null(Credential::WalletInstanceAttestationBlobId))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Credential-CredentialSchemaId")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::CredentialSchemaId)
                        .to_tbl(CredentialSchema::Table)
                        .to_col(CredentialSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Credential-InteractionId")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::InteractionId)
                        .to_tbl(Interaction::Table)
                        .to_col(Interaction::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Credential-KeyId")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::KeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-credential-issuer_certificate")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::IssuerCertificateId)
                        .to_tbl(Certificate::Table)
                        .to_col(Certificate::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_credential_blob_id")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::CredentialBlobId)
                        .to_tbl(BlobStorage::Table)
                        .to_col(BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_holder_identifier")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::HolderIdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_issuer_identifier")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::IssuerIdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_wallet_unit_attestation_blob_id")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::WalletUnitAttestationBlobId)
                        .to_tbl(BlobStorage::Table)
                        .to_col(BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_credential_wallet_instance_attestation_blob_id")
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::WalletInstanceAttestationBlobId)
                        .to_tbl(BlobStorage::Table)
                        .to_col(BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .take(),
        )
        .await?;

    let shared_copied_columns = vec![
        Credential::Id,
        Credential::CreatedDate,
        Credential::LastModified,
        Credential::IssuanceDate,
        Credential::DeletedAt,
        Credential::Protocol,
        Credential::CredentialSchemaId,
        Credential::InteractionId,
        Credential::KeyId,
        Credential::Role,
        Credential::RedirectUri,
        Credential::State,
        Credential::SuspendEndDate,
        Credential::HolderIdentifierId,
        Credential::IssuerIdentifierId,
        Credential::IssuerCertificateId,
        Credential::Profile,
        Credential::CredentialBlobId,
        Credential::WalletUnitAttestationBlobId,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(CredentialNew::Table)
                .columns(
                    [
                        [Credential::WalletInstanceAttestationBlobId].as_slice(),
                        shared_copied_columns.as_slice(),
                    ]
                    .concat(),
                )
                .select_from(
                    Query::select()
                        .from(Credential::Table)
                        .columns(
                            [
                                [Credential::WalletAppAttestationBlobId].as_slice(),
                                shared_copied_columns.as_slice(),
                            ]
                            .concat(),
                        )
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(Credential::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(CredentialNew::Table, Credential::Table)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("idx_credential_list")
                .table(Credential::Table)
                .col(Credential::DeletedAt)
                .col(Credential::Role)
                .col(Credential::CreatedDate)
                .col(Credential::Id)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Credential-CreatedDate")
                .table(Credential::Table)
                .col(Credential::CreatedDate)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Credential-DeletedAt")
                .table(Credential::Table)
                .col(Credential::DeletedAt)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Credential-Role")
                .table(Credential::Table)
                .col(Credential::Role)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Credential-State")
                .table(Credential::Table)
                .col(Credential::State)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Credential-SuspendEndDate")
                .table(Credential::Table)
                .col(Credential::SuspendEndDate)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
