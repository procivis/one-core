use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{integer_null, string, string_len_null, string_null, text_null};

use crate::datatype::{timestamp, timestamp_null, uuid_char, uuid_char_null};
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::{
    BlobStorage, Certificate, Credential, CredentialSchema, FK_CREDENTIAL_CREDENTIAL_BLOB,
    FK_CREDENTIAL_CREDENTIAL_SCHEMA, FK_CREDENTIAL_HOLDER_IDENTIFIER, FK_CREDENTIAL_INTERACTION,
    FK_CREDENTIAL_ISSUER_CERTIFICATE, FK_CREDENTIAL_ISSUER_IDENTIFIER, FK_CREDENTIAL_KEY,
    FK_CREDENTIAL_WALLET_INSTANCE_ATTESTATION_BLOB, FK_CREDENTIAL_WALLET_UNIT_ATTESTATION_BLOB,
    INDEX_CREDENTIAL_CREATED_DATE, INDEX_CREDENTIAL_DELETED_AT, INDEX_CREDENTIAL_LIST,
    INDEX_CREDENTIAL_ROLE, INDEX_CREDENTIAL_STATE, INDEX_CREDENTIAL_SUSPEND_END_DATE, Identifier,
    Interaction, Key,
};
use crate::migrations::m20260429_120000_credential_schema_multiformat::CredentialSchemaFormat;
use crate::migrations::m20260526_095002_credential_grouping::CredentialNew as CredentialWithType;

#[derive(DeriveMigrationName)]
pub struct Migration;

const FK_CREDENTIAL_WALLET_KEY_ATTESTATION_BLOB: &str =
    "fk_credential_wallet_key_attestation_blob_id";
const FK_CREDENTIAL_CREDENTIAL: &str = "fk-Credential-Credential";
const FK_CREDENTIAL_FORMAT: &str = "fk-Credential-Format";
const INDEX_CREDENTIAL_TYPE: &str = "index-Credential-Type";
const INDEX_CREDENTIAL_CONSUMED_AT: &str = "index-Credential-ConsumedAt";
const INDEX_CREDENTIAL_ECOSYSTEM: &str = "index-Credential-Ecosystem";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite can only do one alter operation at a time
        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column(integer_null(
                        CredentialSchemaNew::PreferredKeyStorageAttestationLifetime,
                    ))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column(integer_null(
                        CredentialSchemaNew::PreferredInstanceAttestationLifetime,
                    ))
                    .to_owned(),
            )
            .await?;

        disable_foreign_key_checks(manager).await?;
        if manager.get_database_backend() == DbBackend::Sqlite {
            rename_wallet_key_attestation_blob_sqlite(manager).await?;
        } else {
            rename_wallet_key_attestation_blob(manager).await?;
        }
        enable_foreign_key_checks(manager).await?;

        Ok(())
    }
}

async fn rename_wallet_key_attestation_blob(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Credential::Table)
                .drop_foreign_key(Alias::new(FK_CREDENTIAL_WALLET_UNIT_ATTESTATION_BLOB))
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(Credential::Table)
                .rename_column(
                    Credential::WalletUnitAttestationBlobId,
                    CredentialNew::WalletKeyAttestationBlobId,
                )
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(Credential::Table)
                .add_foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_WALLET_KEY_ATTESTATION_BLOB)
                        .from_tbl(Credential::Table)
                        .from_col(CredentialNew::WalletKeyAttestationBlobId)
                        .to_tbl(BlobStorage::Table)
                        .to_col(BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull)
                        .get_foreign_key(),
                )
                .to_owned(),
        )
        .await
}

async fn rename_wallet_key_attestation_blob_sqlite(
    manager: &SchemaManager<'_>,
) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(CredentialNew::Table)
                .col(uuid_char(Credential::Id).primary_key())
                .col(timestamp(Credential::CreatedDate, manager))
                .col(timestamp(Credential::LastModified, manager))
                .col(timestamp_null(Credential::IssuanceDate, manager))
                .col(timestamp_null(Credential::DeletedAt, manager))
                .col(timestamp_null(Credential::SuspendEndDate, manager))
                .col(timestamp_null(CredentialWithType::ConsumedAt, manager))
                .col(timestamp_null(CredentialNew::ExpiresAt, manager))
                .col(string(Credential::Protocol))
                .col(string(Credential::Role))
                .col(string(Credential::State))
                .col(string(CredentialWithType::Type))
                .col(string_null(Credential::Profile))
                .col(string_null(CredentialNew::Ecosystem))
                .col(string_len_null(Credential::RedirectUri, 1000))
                .col(text_null(Credential::WebhookUrl))
                .col(text_null(CredentialNew::EmbeddedDisclosurePolicy))
                .col(text_null(CredentialNew::SubscriberInformation))
                .col(uuid_char(Credential::CredentialSchemaId))
                .col(uuid_char_null(Credential::InteractionId))
                .col(uuid_char_null(Credential::HolderIdentifierId))
                .col(uuid_char_null(Credential::KeyId))
                .col(uuid_char_null(Credential::IssuerIdentifierId))
                .col(uuid_char_null(Credential::IssuerCertificateId))
                .col(uuid_char_null(Credential::CredentialBlobId))
                .col(uuid_char_null(Credential::WalletInstanceAttestationBlobId))
                .col(uuid_char_null(CredentialNew::WalletKeyAttestationBlobId))
                .col(uuid_char_null(CredentialWithType::ParentId))
                .col(uuid_char_null(CredentialNew::Format))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_CREDENTIAL_SCHEMA)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::CredentialSchemaId)
                        .to_tbl(CredentialSchema::Table)
                        .to_col(CredentialSchema::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_INTERACTION)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::InteractionId)
                        .to_tbl(Interaction::Table)
                        .to_col(Interaction::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_HOLDER_IDENTIFIER)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::HolderIdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_KEY)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::KeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_ISSUER_IDENTIFIER)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::IssuerIdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_ISSUER_CERTIFICATE)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::IssuerCertificateId)
                        .to_tbl(Certificate::Table)
                        .to_col(Certificate::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_CREDENTIAL_BLOB)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::CredentialBlobId)
                        .to_tbl(BlobStorage::Table)
                        .to_col(BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_WALLET_INSTANCE_ATTESTATION_BLOB)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::WalletInstanceAttestationBlobId)
                        .to_tbl(BlobStorage::Table)
                        .to_col(BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_WALLET_KEY_ATTESTATION_BLOB)
                        .from_tbl(CredentialNew::Table)
                        .from_col(CredentialNew::WalletKeyAttestationBlobId)
                        .to_tbl(BlobStorage::Table)
                        .to_col(BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_CREDENTIAL)
                        .from_tbl(CredentialNew::Table)
                        .from_col(CredentialWithType::ParentId)
                        .to_tbl(Credential::Table)
                        .to_col(Credential::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_FORMAT)
                        .from_tbl(CredentialNew::Table)
                        .from_col(CredentialNew::Format)
                        .to_tbl(CredentialSchemaFormat::Table)
                        .to_col(CredentialSchemaFormat::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns: Vec<DynIden> = vec![
        Credential::Id.into_iden(),
        Credential::CreatedDate.into_iden(),
        Credential::LastModified.into_iden(),
        Credential::IssuanceDate.into_iden(),
        Credential::DeletedAt.into_iden(),
        Credential::SuspendEndDate.into_iden(),
        CredentialWithType::ConsumedAt.into_iden(),
        CredentialNew::ExpiresAt.into_iden(),
        Credential::Protocol.into_iden(),
        Credential::Role.into_iden(),
        Credential::State.into_iden(),
        CredentialWithType::Type.into_iden(),
        Credential::Profile.into_iden(),
        CredentialNew::Ecosystem.into_iden(),
        Credential::RedirectUri.into_iden(),
        Credential::WebhookUrl.into_iden(),
        CredentialNew::EmbeddedDisclosurePolicy.into_iden(),
        CredentialNew::SubscriberInformation.into_iden(),
        Credential::CredentialSchemaId.into_iden(),
        Credential::InteractionId.into_iden(),
        Credential::HolderIdentifierId.into_iden(),
        Credential::KeyId.into_iden(),
        Credential::IssuerIdentifierId.into_iden(),
        Credential::IssuerCertificateId.into_iden(),
        Credential::CredentialBlobId.into_iden(),
        Credential::WalletInstanceAttestationBlobId.into_iden(),
        CredentialWithType::ParentId.into_iden(),
        CredentialNew::Format.into_iden(),
    ];
    let mut insert_columns = copied_columns.clone();
    insert_columns.push(CredentialNew::WalletKeyAttestationBlobId.into_iden());
    let mut select_columns = copied_columns;
    select_columns.push(Credential::WalletUnitAttestationBlobId.into_iden());

    manager
        .exec_stmt(
            Query::insert()
                .into_table(CredentialNew::Table)
                .columns(insert_columns)
                .select_from(
                    Query::select()
                        .from(Credential::Table)
                        .columns(select_columns)
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
        Index::create()
            .if_not_exists()
            .name(INDEX_CREDENTIAL_TYPE)
            .table(Credential::Table)
            .col(CredentialWithType::Type)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_CREDENTIAL_CONSUMED_AT)
            .table(Credential::Table)
            .col(CredentialWithType::ConsumedAt)
            .to_owned(),
        Index::create()
            .if_not_exists()
            .name(INDEX_CREDENTIAL_ECOSYSTEM)
            .table(Credential::Table)
            .col(CredentialNew::Ecosystem)
            .to_owned(),
    ];
    for index in indexes {
        manager.create_index(index).await?;
    }

    Ok(())
}

#[derive(DeriveIden)]
enum CredentialSchemaNew {
    PreferredKeyStorageAttestationLifetime,
    PreferredInstanceAttestationLifetime,
}

#[derive(DeriveIden)]
enum CredentialNew {
    Table,
    WalletKeyAttestationBlobId,
    EmbeddedDisclosurePolicy,
    SubscriberInformation,
    Ecosystem,
    ExpiresAt,
    Format,
}
