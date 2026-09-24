use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_len_null, string_null, text_null};

use crate::datatype::{timestamp, timestamp_null, uuid_char, uuid_char_null};
use crate::migrations::m20260417_150300_initial::{
    BlobStorage, Certificate, Credential, CredentialSchema, FK_CREDENTIAL_CREDENTIAL_BLOB,
    FK_CREDENTIAL_CREDENTIAL_SCHEMA, FK_CREDENTIAL_HOLDER_IDENTIFIER, FK_CREDENTIAL_INTERACTION,
    FK_CREDENTIAL_ISSUER_CERTIFICATE, FK_CREDENTIAL_ISSUER_IDENTIFIER, FK_CREDENTIAL_KEY,
    FK_CREDENTIAL_WALLET_INSTANCE_ATTESTATION_BLOB, FK_CREDENTIAL_WALLET_UNIT_ATTESTATION_BLOB,
    INDEX_CREDENTIAL_CREATED_DATE, INDEX_CREDENTIAL_DELETED_AT, INDEX_CREDENTIAL_LIST,
    INDEX_CREDENTIAL_ROLE, INDEX_CREDENTIAL_STATE, INDEX_CREDENTIAL_SUSPEND_END_DATE, Identifier,
    Interaction, Key,
};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const FK_CREDENTIAL_CREDENTIAL: &str = "fk-Credential-Credential";
const INDEX_CREDENTIAL_TYPE: &str = "index-Credential-Type";
const INDEX_CREDENTIAL_CONSUMED_AT: &str = "index-Credential-ConsumedAt";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite can only do one alter operation at a time
        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(string_null(CredentialNew::Type))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(timestamp_null(CredentialNew::ConsumedAt, manager))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(uuid_char_null(CredentialNew::ParentId))
                    .to_owned(),
            )
            .await?;
        manager
            .exec_stmt(
                Query::update()
                    .table(Credential::Table)
                    .value(CredentialNew::Type, "SINGLE")
                    .to_owned(),
            )
            .await?;

        if manager.supported_db_type() == SupportedDbType::Sqlite {
            sqlite_type_not_null(manager).await?;
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(Credential::Table)
                        .modify_column(string(CredentialNew::Type))
                        .add_foreign_key(
                            TableForeignKey::new()
                                .name(FK_CREDENTIAL_CREDENTIAL)
                                .from_tbl(Credential::Table)
                                .from_col(CredentialNew::ParentId)
                                .to_tbl(Credential::Table)
                                .to_col(Credential::Id),
                        )
                        .to_owned(),
                )
                .await?;
        }

        // Add indices for new columns
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(INDEX_CREDENTIAL_TYPE)
                    .table(Credential::Table)
                    .col(CredentialNew::Type)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(INDEX_CREDENTIAL_CONSUMED_AT)
                    .table(Credential::Table)
                    .col(CredentialNew::ConsumedAt)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

async fn sqlite_type_not_null(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

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
                .col(timestamp_null(CredentialNew::ConsumedAt, manager))
                .col(string(Credential::Protocol))
                .col(string(Credential::Role))
                .col(string(Credential::State))
                .col(string(CredentialNew::Type))
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
                .col(uuid_char_null(CredentialNew::ParentId))
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
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_CREDENTIAL)
                        .from_tbl(Credential::Table)
                        .from_col(CredentialNew::ParentId)
                        .to_tbl(Credential::Table)
                        .to_col(Credential::Id),
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
        Credential::Protocol.into_iden(),
        Credential::CredentialSchemaId.into_iden(),
        Credential::InteractionId.into_iden(),
        Credential::KeyId.into_iden(),
        Credential::Role.into_iden(),
        Credential::RedirectUri.into_iden(),
        Credential::State.into_iden(),
        Credential::SuspendEndDate.into_iden(),
        Credential::HolderIdentifierId.into_iden(),
        Credential::IssuerIdentifierId.into_iden(),
        Credential::IssuerCertificateId.into_iden(),
        Credential::Profile.into_iden(),
        Credential::CredentialBlobId.into_iden(),
        Credential::WalletUnitAttestationBlobId.into_iden(),
        Credential::WalletInstanceAttestationBlobId.into_iden(),
        Credential::WebhookUrl.into_iden(),
        CredentialNew::Type.into_iden(),
        CredentialNew::ConsumedAt.into_iden(),
        CredentialNew::ParentId.into_iden(),
    ];

    manager
        .exec_stmt(
            Query::insert()
                .into_table(CredentialNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(Credential::Table)
                        .columns(copied_columns)
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
    ];
    for index in indexes {
        manager.create_index(index).await?;
    }
    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;
    Ok(())
}

#[derive(DeriveIden)]
pub enum CredentialNew {
    Table,
    Type,
    ConsumedAt,
    ParentId,
}
